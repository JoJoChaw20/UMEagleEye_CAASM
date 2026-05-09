"""
UMEagleEye - AI Advisory Service (FR-05).
RAG pipeline: pgvector retrieval (fastembed/ONNX) + DeepSeek via OpenRouter.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from functools import lru_cache

import numpy as np
from openai import OpenAI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import PlaybookChunk, Advisory, Event

logger = logging.getLogger(__name__)

# ── OpenRouter client (OpenAI-compatible) ──
def _get_openrouter_client() -> OpenAI:
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=settings.OPENROUTER_API_KEY,
    )

# ── Lightweight ONNX embedding model (fastembed, no PyTorch needed) ──
@lru_cache(maxsize=1)
def _get_embedding_model():
    """Load fastembed model once and cache it. Downloads ~50MB ONNX model on first use."""
    try:
        from fastembed import TextEmbedding
        logger.info("Loading fastembed model: BAAI/bge-small-en-v1.5")
        return TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
    except Exception as e:
        logger.error(f"Failed to load fastembed model: {e}")
        return None

EMBEDDING_DIM = 384  # BAAI/bge-small-en-v1.5 output dimension

SYSTEM_PROMPT = """You are UMEagleEye, an AI security advisor for Malaysian SMEs.
You provide prescriptive, step-by-step remediation guidance for cybersecurity incidents.

RULES:
1. Always provide specific, copy-pasteable CLI commands when applicable
2. Structure responses as JSON with "summary" and "recommended_action" fields
3. Include exact commands (e.g., `sudo ufw deny from <IP>`, `sudo systemctl stop apache2`)
4. Reference relevant MITRE ATT&CK techniques when known
5. Keep language clear for non-expert IT staff
6. Never suggest actions that could cause data loss without explicit warnings
7. Prioritize containment, then investigation, then remediation

Respond ONLY with valid JSON in this format:
{
  "summary": "Plain-language explanation of the issue",
  "recommended_action": "Step-by-step fix with specific commands",
  "severity_assessment": "Critical/High/Medium/Low",
  "mitre_technique": "T-ID if applicable"
}"""


class AdvisoryService:
    """RAG-based AI advisory generation using DeepSeek (OpenRouter) + pgvector."""

    # ═══════════════════════════════════════════════════════════
    # FR-05-01: RAG Knowledge Base Generation
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    async def embed_text(text_content: str) -> List[float]:
        """Generate embedding vector using fastembed (ONNX, no GPU/PyTorch needed)."""
        try:
            model = _get_embedding_model()
            if model is None:
                return [0.0] * EMBEDDING_DIM
            # fastembed returns a generator; take the first (and only) result
            embeddings = list(model.embed([text_content]))
            return embeddings[0].tolist()
        except Exception as e:
            logger.error(f"Embedding error: {e}")
            return [0.0] * EMBEDDING_DIM

    @staticmethod
    def embed_text_sync(text_content: str) -> List[float]:
        """Synchronous embedding for Celery workers (fastembed is sync-native)."""
        try:
            model = _get_embedding_model()
            if model is None:
                return [0.0] * EMBEDDING_DIM
            embeddings = list(model.embed([text_content]))
            return embeddings[0].tolist()
        except Exception as e:
            logger.error(f"Sync embedding error: {e}")
            return [0.0] * EMBEDDING_DIM

    @staticmethod
    async def ingest_playbook(
        content: str,
        source_name: str,
        chunk_size: int = 500,
        db: AsyncSession = None,
    ) -> int:
        """Chunk and embed a playbook document into pgvector.

        Args:
            content: Full text content of the playbook
            source_name: Name of the source document
            chunk_size: Characters per chunk
            db: Async database session

        Returns:
            Number of chunks embedded
        """
        # Split into chunks
        chunks = []
        words = content.split()
        current_chunk = []
        current_len = 0

        for word in words:
            current_chunk.append(word)
            current_len += len(word) + 1
            if current_len >= chunk_size:
                chunks.append(" ".join(current_chunk))
                current_chunk = []
                current_len = 0

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        # Embed and store each chunk
        count = 0
        for i, chunk_text in enumerate(chunks):
            embedding = await AdvisoryService.embed_text(chunk_text)

            chunk = PlaybookChunk(
                source_document=source_name,
                content=chunk_text,
                embedding=embedding,
                metadata_json={"chunk_index": i, "total_chunks": len(chunks)},
            )
            db.add(chunk)
            count += 1

        await db.flush()
        logger.info(f"Embedded {count} chunks from {source_name}")
        return count

    @staticmethod
    async def retrieve_context(
        query: str,
        db: AsyncSession,
        top_k: int = 5,
    ) -> List[str]:
        """Retrieve most relevant playbook chunks via pgvector similarity search."""
        try:
            query_embedding = await AdvisoryService.embed_text(query)
            embedding_str = str(query_embedding)

            result = await db.execute(
                text("""
                    SELECT content, 1 - (embedding <=> CAST(:embedding AS vector)) as similarity
                    FROM playbook_chunks
                    WHERE embedding IS NOT NULL
                    ORDER BY embedding <=> CAST(:embedding AS vector)
                    LIMIT :top_k
                """),
                {"embedding": embedding_str, "top_k": top_k},
            )

            rows = result.fetchall()
            return [row[0] for row in rows]

        except Exception as e:
            logger.error(f"RAG retrieval error: {e}")
            return []

    @staticmethod
    def retrieve_context_sync(
        query: str,
        session,
        top_k: int = 5,
    ) -> List[str]:
        """Synchronous version of retrieve_context for Celery workers."""
        try:
            query_embedding = AdvisoryService.embed_text_sync(query)
            embedding_str = str(query_embedding)

            result = session.execute(
                text("""
                    SELECT content, 1 - (embedding <=> CAST(:embedding AS vector)) as similarity
                    FROM playbook_chunks
                    WHERE embedding IS NOT NULL
                    ORDER BY embedding <=> CAST(:embedding AS vector)
                    LIMIT :top_k
                """),
                {"embedding": embedding_str, "top_k": top_k},
            )

            rows = result.fetchall()
            return [row[0] for row in rows]
        except Exception as e:
            logger.error(f"Sync RAG retrieval error: {e}")
            return []

    # ═══════════════════════════════════════════════════════════
    # FR-05-02: LLM Prescriptive Inference
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    async def generate_advisory(
        event_data: Dict[str, Any],
        asset_data: Dict[str, Any],
        db: AsyncSession = None,
    ) -> Dict[str, str]:
        """Generate prescriptive advisory using DeepSeek (OpenRouter) with RAG context.

        Args:
            event_data: Event details (type, severity, details JSON)
            asset_data: Asset context (hostname, IP, criticality)
            db: Database session for RAG retrieval

        Returns:
            Dict with summary and recommended_action
        """
        if not settings.OPENROUTER_API_KEY:
            return {
                "summary": f"Security event detected: {event_data.get('event_type', 'unknown')}",
                "recommended_action": "OpenRouter API key not configured. Please review the event manually.",
            }

        response_text = ""
        try:
            # Build safe prompt (no PII per FR-05 requirements)
            alert_summary = (
                f"Event Type: {event_data.get('event_type', 'unknown')}\n"
                f"Severity: {event_data.get('severity', 'medium')}\n"
                f"Asset Type: {asset_data.get('device_type', 'server')}\n"
                f"Asset Criticality: {asset_data.get('criticality_score', 5)}/10\n"
                f"Internet Facing: {asset_data.get('is_internet_facing', False)}\n"
                f"Details: {json.dumps(event_data.get('details', {}), indent=2)}"
            )

            # Retrieve RAG context
            rag_context = ""
            if db:
                if isinstance(db, AsyncSession):
                    chunks = await AdvisoryService.retrieve_context(alert_summary, db)
                else:
                    # Handle sync session (Celery workers)
                    chunks = AdvisoryService.retrieve_context_sync(alert_summary, db)

                if chunks:
                    rag_context = "\n\nRELEVANT PLAYBOOK CONTEXT:\n" + "\n---\n".join(chunks)

            # Call DeepSeek via OpenRouter
            client = _get_openrouter_client()
            prompt = f"{alert_summary}{rag_context}"

            completion = client.chat.completions.create(
                model=settings.OPENROUTER_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=2048,
                extra_headers={
                    "HTTP-Referer": "https://umeagleeye.local",
                    "X-Title": "UMEagleEye CAASM",
                },
            )

            response_text = completion.choices[0].message.content.strip()

            # Strip markdown code fences if present
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.rstrip("`").strip()

            result = json.loads(response_text)
            return {
                "summary": result.get("summary", "Advisory generated"),
                "recommended_action": result.get("recommended_action", "Review event details"),
            }

        except json.JSONDecodeError:
            return {
                "summary": f"Security alert: {event_data.get('event_type', 'unknown')} detected",
                "recommended_action": response_text if response_text else "Review manually",
            }
        except Exception as e:
            logger.error(f"DeepSeek advisory error: {e}")
            return {
                "summary": f"Auto-advisory for {event_data.get('event_type', 'unknown')} event",
                "recommended_action": f"Error generating AI advisory: {str(e)}. Please review the event manually.",
            }
