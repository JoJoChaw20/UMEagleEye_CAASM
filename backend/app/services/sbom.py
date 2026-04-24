"""
UMEagleEye - SBOM Generation Service (FR-02-01, FR-02-02).
Uses Syft to generate CycloneDX v1.5 SBOMs.
"""

import json
import subprocess
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class SBOMService:
    """Handles SBOM generation via Syft and dependency parsing."""

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
            # Extract license info if available
            for lic in component.get("licenses", []):
                if "license" in lic:
                    dep["licenses"].append(
                        lic["license"].get("id", lic["license"].get("name", ""))
                    )
            dependencies.append(dep)

        return dependencies
