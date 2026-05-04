"""
UMEagleEye - Asset Relationship Service.
Infers network relationships between assets, computes blast radius
via BFS traversal, and provides graph data for visualisation.
"""

import logging
import ipaddress
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy import select, func, and_, or_, delete
from sqlalchemy.orm import Session

from app.db.models import Asset, AssetRelationship
from app.db.enums import RelationshipType

logger = logging.getLogger(__name__)


class RelationshipService:
    """Handles asset relationship inference, graph queries, and blast-radius analysis."""

    # ═══════════════════════════════════════════════════════════
    # Relationship Inference from Scan Data
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def infer_relationships(session: Session) -> Dict[str, Any]:
        """Auto-infer asset relationships from scan data.

        Heuristics:
        1. same_subnet: assets sharing a /24 subnet
        2. connects_to: asset A has open port pointing to asset B's IP
        3. exposes_service: asset exposes a well-known service port

        Returns summary with counts of relationships created.
        """
        assets = session.execute(select(Asset)).scalars().all()
        if not assets:
            return {"new_relationships": 0, "total_assets": 0}

        new_count = 0
        # Build IP lookup for fast matching
        ip_to_asset: Dict[str, Asset] = {}
        for asset in assets:
            ip_str = str(asset.ip_address)
            ip_to_asset[ip_str] = asset

        # 1. Infer same_subnet relationships (/24 grouping)
        subnet_groups: Dict[str, List[Asset]] = defaultdict(list)
        for asset in assets:
            try:
                ip = ipaddress.ip_address(str(asset.ip_address))
                # Group by /24 subnet
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnet_groups[str(network)].append(asset)
            except (ValueError, TypeError):
                continue

        for subnet, group_assets in subnet_groups.items():
            if len(group_assets) < 2:
                continue
            # Create pairwise same_subnet relationships
            for i in range(len(group_assets)):
                for j in range(i + 1, len(group_assets)):
                    a, b = group_assets[i], group_assets[j]
                    created = RelationshipService._upsert_relationship(
                        session, a.asset_id, b.asset_id,
                        RelationshipType.SAME_SUBNET,
                        metadata={"subnet": subnet},
                        confidence=0.95,
                    )
                    if created:
                        new_count += 1

        # 2. Infer connects_to from open ports
        for asset in assets:
            os_info = asset.os_info or {}
            open_ports = os_info.get("open_ports", [])
            if not open_ports:
                continue

            for port_info in open_ports:
                service_name = port_info.get("service_name", "").lower()
                port_num = port_info.get("port", 0)

                # Check if this service might connect to another asset
                # (e.g., a database client connecting to a DB server)
                for other_ip, other_asset in ip_to_asset.items():
                    if other_asset.asset_id == asset.asset_id:
                        continue

                    other_ports = (other_asset.os_info or {}).get("open_ports", [])
                    for other_port in other_ports:
                        other_port_num = other_port.get("port", 0)
                        other_service = other_port.get("service_name", "").lower()

                        # If this asset has an HTTP/HTTPS port and another has a backend service
                        if _is_frontend_to_backend(port_num, service_name, other_port_num, other_service):
                            created = RelationshipService._upsert_relationship(
                                session, asset.asset_id, other_asset.asset_id,
                                RelationshipType.CONNECTS_TO,
                                metadata={
                                    "source_port": port_num,
                                    "target_port": other_port_num,
                                    "source_service": service_name,
                                    "target_service": other_service,
                                },
                                confidence=0.70,
                            )
                            if created:
                                new_count += 1

                # 3. Detect service exposure (internet-facing services)
                if asset.is_internet_facing and port_num in (80, 443, 8080, 8443):
                    # This asset exposes a web service — link to any backend asset on same subnet
                    try:
                        asset_ip = ipaddress.ip_address(str(asset.ip_address))
                        asset_subnet = ipaddress.ip_network(f"{asset_ip}/24", strict=False)
                    except (ValueError, TypeError):
                        continue

                    for other_ip, other_asset in ip_to_asset.items():
                        if other_asset.asset_id == asset.asset_id:
                            continue
                        try:
                            other_ip_obj = ipaddress.ip_address(other_ip)
                            if other_ip_obj in asset_subnet:
                                other_ports = (other_asset.os_info or {}).get("open_ports", [])
                                backend_ports = [p for p in other_ports if p.get("port", 0) in (
                                    3306, 5432, 27017, 6379, 9200, 8000, 8080
                                )]
                                if backend_ports:
                                    created = RelationshipService._upsert_relationship(
                                        session, asset.asset_id, other_asset.asset_id,
                                        RelationshipType.EXPOSES_SERVICE,
                                        metadata={
                                            "exposed_port": port_num,
                                            "backend_ports": [p["port"] for p in backend_ports],
                                        },
                                        confidence=0.60,
                                    )
                                    if created:
                                        new_count += 1
                        except (ValueError, TypeError):
                            continue

        session.commit()
        total_relationships = session.execute(
            select(func.count(AssetRelationship.relationship_id))
        ).scalar() or 0

        logger.info(f"Relationship inference complete: {new_count} new, {total_relationships} total")
        return {
            "new_relationships": new_count,
            "total_relationships": total_relationships,
            "total_assets": len(assets),
        }

    @staticmethod
    def _upsert_relationship(
        session: Session,
        source_id: UUID,
        target_id: UUID,
        rel_type: RelationshipType,
        metadata: Optional[dict] = None,
        confidence: float = 0.5,
    ) -> bool:
        """Insert a relationship if it doesn't already exist. Returns True if created."""
        existing = session.execute(
            select(AssetRelationship).where(
                and_(
                    AssetRelationship.source_asset_id == source_id,
                    AssetRelationship.target_asset_id == target_id,
                    AssetRelationship.relationship_type == rel_type,
                )
            )
        ).scalar_one_or_none()

        if existing:
            # Update metadata if changed
            if metadata and existing.metadata_json != metadata:
                existing.metadata_json = metadata
                existing.confidence = confidence
            return False

        rel = AssetRelationship(
            source_asset_id=source_id,
            target_asset_id=target_id,
            relationship_type=rel_type,
            metadata_json=metadata,
            confidence=confidence,
        )
        session.add(rel)
        return True

    # ═══════════════════════════════════════════════════════════
    # Graph Retrieval
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def get_asset_graph(session: Session, asset_id: Optional[UUID] = None) -> Dict[str, Any]:
        """Build the full asset relationship graph or a subgraph centered on one asset.

        Returns nodes and edges suitable for frontend visualisation.
        """
        # Get relationships
        rel_query = select(AssetRelationship)
        if asset_id:
            rel_query = rel_query.where(
                or_(
                    AssetRelationship.source_asset_id == asset_id,
                    AssetRelationship.target_asset_id == asset_id,
                )
            )
        relationships = session.execute(rel_query).scalars().all()

        # Collect all referenced asset IDs
        asset_ids: Set[UUID] = set()
        for rel in relationships:
            asset_ids.add(rel.source_asset_id)
            asset_ids.add(rel.target_asset_id)

        # If centered on an asset, also include the asset itself even if no edges
        if asset_id:
            asset_ids.add(asset_id)

        # If no relationships exist, show all assets as isolated nodes
        if not relationships and not asset_id:
            all_assets = session.execute(select(Asset)).scalars().all()
            asset_ids = {a.asset_id for a in all_assets}

        # Fetch asset details
        assets_query = select(Asset).where(Asset.asset_id.in_(list(asset_ids)))
        assets = session.execute(assets_query).scalars().all()

        # Count edges per asset
        edge_counts: Dict[UUID, int] = defaultdict(int)
        for rel in relationships:
            edge_counts[rel.source_asset_id] += 1
            edge_counts[rel.target_asset_id] += 1

        nodes = []
        for asset in assets:
            nodes.append({
                "asset_id": str(asset.asset_id),
                "hostname": asset.hostname,
                "ip_address": str(asset.ip_address),
                "device_type": asset.device_type.value if asset.device_type else "unknown",
                "criticality_score": asset.criticality_score,
                "is_internet_facing": asset.is_internet_facing,
                "edge_count": edge_counts.get(asset.asset_id, 0),
            })

        edges = []
        for rel in relationships:
            edges.append({
                "relationship_id": str(rel.relationship_id),
                "source": str(rel.source_asset_id),
                "target": str(rel.target_asset_id),
                "relationship_type": rel.relationship_type.value,
                "confidence": float(rel.confidence) if rel.confidence else None,
                "metadata_json": rel.metadata_json,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        }

    # ═══════════════════════════════════════════════════════════
    # Blast Radius (BFS Traversal)
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def compute_blast_radius(
        session: Session,
        origin_asset_id: UUID,
        max_depth: int = 3,
    ) -> Dict[str, Any]:
        """Compute blast radius via BFS from a given asset.

        Traverses all outgoing AND incoming edges to find downstream
        affected assets up to max_depth hops.

        Returns affected assets with depth and path information.
        """
        # Build adjacency list from all relationships
        all_rels = session.execute(select(AssetRelationship)).scalars().all()
        adjacency: Dict[UUID, List[Tuple[UUID, str]]] = defaultdict(list)

        for rel in all_rels:
            adjacency[rel.source_asset_id].append(
                (rel.target_asset_id, rel.relationship_type.value)
            )
            adjacency[rel.target_asset_id].append(
                (rel.source_asset_id, rel.relationship_type.value)
            )

        # BFS
        visited: Set[UUID] = {origin_asset_id}
        queue: deque = deque()
        queue.append((origin_asset_id, 0, [str(origin_asset_id)]))

        affected: List[Dict[str, Any]] = []

        while queue:
            current_id, depth, path = queue.popleft()

            if depth >= max_depth:
                continue

            for neighbor_id, rel_type in adjacency.get(current_id, []):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    new_path = path + [str(neighbor_id)]
                    affected.append({
                        "asset_id": neighbor_id,
                        "depth": depth + 1,
                        "path": new_path,
                        "via_relationship": rel_type,
                    })
                    queue.append((neighbor_id, depth + 1, new_path))

        # Enrich affected assets with details
        if affected:
            affected_ids = [a["asset_id"] for a in affected]
            assets = session.execute(
                select(Asset).where(Asset.asset_id.in_(affected_ids))
            ).scalars().all()
            asset_map = {a.asset_id: a for a in assets}

            for item in affected:
                asset = asset_map.get(item["asset_id"])
                if asset:
                    item["hostname"] = asset.hostname
                    item["ip_address"] = str(asset.ip_address)
                    item["criticality_score"] = asset.criticality_score
                    item["device_type"] = asset.device_type.value if asset.device_type else "unknown"

        return {
            "origin_asset_id": str(origin_asset_id),
            "affected_assets": affected,
            "total_affected": len(affected),
            "max_depth": max_depth,
        }


# ── Helper Functions ──

def _is_frontend_to_backend(
    port_a: int, service_a: str,
    port_b: int, service_b: str,
) -> bool:
    """Determine if port_a's service likely connects to port_b's backend service."""
    frontend_ports = {80, 443, 8080, 8443, 3000, 5173}
    backend_ports = {3306, 5432, 27017, 6379, 9200, 9300, 8000, 8080, 5000}

    # Frontend → Backend pattern
    if port_a in frontend_ports and port_b in backend_ports:
        return True

    # Application → Database pattern
    app_services = {"http", "https", "nginx", "apache", "node", "gunicorn", "uvicorn"}
    db_services = {"mysql", "postgresql", "mongodb", "redis", "elasticsearch"}

    if service_a in app_services and service_b in db_services:
        return True

    return False
