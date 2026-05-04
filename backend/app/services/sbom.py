"""
UMEagleEye - SBOM Generation Service (FR-02-01, FR-02-02).
Uses Syft to generate CycloneDX v1.5 SBOMs.
Stores raw SBOM JSON in Google Cloud Storage (GCS).
"""

import json
import subprocess
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from app.core.config import settings

logger = logging.getLogger(__name__)


class SBOMService:
    """Handles SBOM generation via Syft, GCS upload, and dependency parsing."""

    @staticmethod
    def generate_sbom(
        target: str,
        output_format: str = "cyclonedx-json",
        timeout: int = 300,
    ) -> Optional[Dict[str, Any]]:
        """Generate a CycloneDX v1.5 SBOM for a target using Syft.

        Args:
            target: Container image, directory, or file path to scan
            output_format: Syft output format
            timeout: Execution timeout in seconds

        Returns:
            Parsed SBOM JSON dict or None on failure
        """
        try:
            cmd = [
                "syft",
                target,
                "-o", output_format,
                "--quiet",
            ]
            logger.info(f"Generating SBOM for: {target}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                logger.warning(f"Syft returned code {result.returncode}: {result.stderr}")
                return None

            sbom = json.loads(result.stdout)
            logger.info(f"SBOM generated: {len(sbom.get('components', []))} components found")
            return sbom

        except subprocess.TimeoutExpired:
            logger.error(f"Syft timed out after {timeout}s for {target}")
            return None
        except FileNotFoundError:
            logger.error("Syft binary not found. Ensure it is installed.")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Syft output: {e}")
            return None

    @staticmethod
    def upload_sbom_to_gcs(sbom_data: Dict[str, Any], asset_id: str) -> Optional[str]:
        """Upload raw SBOM JSON to Google Cloud Storage (FR-02-01).

        Args:
            sbom_data: Full CycloneDX SBOM JSON dict
            asset_id: UUID of the associated asset

        Returns:
            GCS path string (gs://bucket/path) or None on failure
        """
        if not settings.GCS_SERVICE_ACCOUNT_KEY or not settings.GCS_BUCKET_NAME:
            logger.info("GCS not configured, skipping SBOM upload")
            return None

        try:
            import json
            from google.cloud import storage
            from google.oauth2 import service_account

            if settings.GCS_SERVICE_ACCOUNT_KEY:
                # Load credentials from the minified JSON string
                creds_info = json.loads(settings.GCS_SERVICE_ACCOUNT_KEY)
                credentials = service_account.Credentials.from_service_account_info(creds_info)
                client = storage.Client(credentials=credentials)
            else:
                client = storage.Client()
                
            bucket = client.bucket(settings.GCS_BUCKET_NAME)

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            blob_path = f"sboms/{asset_id}/{timestamp}.json"
            blob = bucket.blob(blob_path)

            sbom_json = json.dumps(sbom_data, indent=2)
            blob.upload_from_string(sbom_json, content_type="application/json")

            gcs_path = f"gs://{settings.GCS_BUCKET_NAME}/{blob_path}"
            logger.info(f"SBOM uploaded to GCS: {gcs_path} ({len(sbom_json)} bytes)")
            return gcs_path

        except Exception as e:
            logger.error(f"GCS SBOM upload error: {e}")
            return None

    @staticmethod
    def parse_dependencies(sbom_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Parse SBOM components into a flat dependency list (FR-02-02).

        Returns:
            List of dicts with name, version, type, purl for each component
        """
        dependencies = []
        for component in sbom_data.get("components", []):
            dep = {
                "name": component.get("name", ""),
                "version": component.get("version", ""),
                "type": component.get("type", "library"),
                "purl": component.get("purl", ""),
                "licenses": [],
            }

            # Infer package manager from purl
            purl = dep["purl"]
            if "pkg:pypi" in purl:
                dep["package_manager"] = "pip"
            elif "pkg:maven" in purl:
                dep["package_manager"] = "maven"
            elif "pkg:npm" in purl:
                dep["package_manager"] = "npm"
            elif "pkg:apk" in purl:
                dep["package_manager"] = "apk"
            elif "pkg:deb" in purl:
                dep["package_manager"] = "deb"
            elif "pkg:rpm" in purl:
                dep["package_manager"] = "rpm"
            elif "pkg:golang" in purl:
                dep["package_manager"] = "go"
            else:
                dep["package_manager"] = "system"

            # Extract license info if available
            for lic in component.get("licenses", []):
                if "license" in lic:
                    dep["licenses"].append(
                        lic["license"].get("id", lic["license"].get("name", ""))
                    )
            dependencies.append(dep)

        return dependencies
