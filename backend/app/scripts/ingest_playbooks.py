import asyncio
import os
import sys
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Add the parent directory to sys.path so we can import app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.core.config import settings
from app.services.advisory import AdvisoryService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def ingest_all_playbooks():
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    playbooks_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "playbooks"))
    
    if not os.path.exists(playbooks_dir):
        logger.error(f"Playbooks directory not found: {playbooks_dir}")
        return

    async with async_session() as session:
        for filename in os.listdir(playbooks_dir):
            if filename.endswith(".md"):
                file_path = os.path.join(playbooks_dir, filename)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                logger.info(f"Ingesting playbook: {filename}")
                await AdvisoryService.ingest_playbook(
                    content=content,
                    source_name=filename,
                    db=session
                )
        
        await session.commit()
    
    await engine.dispose()
    logger.info("Playbook ingestion complete.")

if __name__ == "__main__":
    asyncio.run(ingest_all_playbooks())
