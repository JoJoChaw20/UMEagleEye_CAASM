"""
UMEagleEye - Hybrid Asset Discovery Service (FR-01).
Active scanning via Nmap/Masscan and passive listening via Scapy.
"""

import json
import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class DiscoveryService:
    """Handles active and passive network discovery."""

    # ═══════════════════════════════════════════════════════════
    # FR-01-01: Active Scanning API Wrapper
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def run_nmap_scan(
        target_subnet: str,
        rate_limit: int = 1000,
        timeout: int = 300,
    ) -> List[Dict[str, Any]]:
        """Execute Nmap against target subnet and parse output into standardized JSON.

        Args:
            target_subnet: CIDR notation subnet (e.g., '192.168.1.0/24')
            rate_limit: Maximum packets per second
            timeout: Execution timeout in seconds

        Returns:
            List of discovered host dictionaries with ports and services
        """
        try:
            cmd = [
                "nmap", "-sV", "-O", "--osscan-guess",
                "-T4", f"--max-rate={rate_limit}",
                "-oX", "-",  # XML output to stdout
                target_subnet,
            ]
            logger.info(f"Running Nmap scan: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                logger.warning(f"Nmap returned code {result.returncode}: {result.stderr}")

            return DiscoveryService._parse_nmap_xml(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out after {timeout}s for {target_subnet}")
            return []
        except FileNotFoundError:
            logger.error("Nmap binary not found. Ensure it is installed.")
            return []
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return []

    @staticmethod
    def run_masscan(
        target_subnet: str,
        ports: str = "1-65535",
        rate_limit: int = 1000,
        timeout: int = 600,
    ) -> List[Dict[str, Any]]:
        """Execute Masscan for high-speed bulk port sweeping.

        Args:
            target_subnet: CIDR notation subnet
            ports: Port range string
            rate_limit: Packets per second
            timeout: Execution timeout

        Returns:
            List of discovered host dictionaries
        """
        try:
            cmd = [
                "masscan",
                target_subnet,
                f"-p{ports}",
                f"--rate={rate_limit}",
                "-oJ", "-",  # JSON output to stdout
                "--wait=3",
            ]
            logger.info(f"Running Masscan: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            return DiscoveryService._parse_masscan_json(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error(f"Masscan timed out after {timeout}s for {target_subnet}")
            return []
        except FileNotFoundError:
            logger.error("Masscan binary not found. Ensure it is installed.")
            return []
        except Exception as e:
            logger.error(f"Masscan error: {e}")
            return []

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output into standardized host dictionaries."""
        hosts = []
        try:
            root = ET.fromstring(xml_output)

            for host_elem in root.findall(".//host"):
                status = host_elem.find("status")
                if status is None or status.get("state") != "up":
                    continue

                host_data = {
                    "ip_address": None,
                    "mac_address": None,
                    "hostname": None,
                    "os_info": {},
                    "hardware_vendor": None,
                    "ports": [],
                    "last_scanned": datetime.now(timezone.utc).isoformat(),
                    "scan_source": "nmap",
                }

                # IP and MAC addresses
                for addr in host_elem.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        host_data["ip_address"] = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        host_data["mac_address"] = addr.get("addr")
                        host_data["hardware_vendor"] = addr.get("vendor", "")

                # Hostname
                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    name_elem = hostnames.find("hostname")
                    if name_elem is not None:
                        host_data["hostname"] = name_elem.get("name")

                # OS detection
                os_elem = host_elem.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host_data["os_info"] = {
                            "name": osmatch.get("name", ""),
                            "accuracy": osmatch.get("accuracy", ""),
                        }

                # Ports and services
                ports_elem = host_elem.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            service = port.find("service")
                            port_data = {
                                "port": int(port.get("portid", 0)),
                                "protocol": port.get("protocol", "tcp"),
                                "state": "open",
                                "service_name": service.get("name", "") if service is not None else "",
                                "service_version": service.get("version", "") if service is not None else "",
                                "product": service.get("product", "") if service is not None else "",
                            }
                            host_data["ports"].append(port_data)

                if host_data["ip_address"]:
                    hosts.append(host_data)

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")

        return hosts

    @staticmethod
    def _parse_masscan_json(json_output: str) -> List[Dict[str, Any]]:
        """Parse Masscan JSON output into standardized host dictionaries."""
        hosts_dict = {}
        try:
            # Masscan JSON may have trailing comma issues
            clean = json_output.strip().rstrip(",")
            if not clean.startswith("["):
                clean = f"[{clean}]"

            data = json.loads(clean)

            for entry in data:
                ip = entry.get("ip", "")
                if not ip:
                    continue

                if ip not in hosts_dict:
                    hosts_dict[ip] = {
                        "ip_address": ip,
                        "mac_address": None,
                        "hostname": None,
                        "os_info": {},
                        "hardware_vendor": None,
                        "ports": [],
                        "last_scanned": datetime.now(timezone.utc).isoformat(),
                        "scan_source": "masscan",
                    }

                for port_info in entry.get("ports", []):
                    hosts_dict[ip]["ports"].append({
                        "port": port_info.get("port", 0),
                        "protocol": port_info.get("proto", "tcp"),
                        "state": "open",
                        "service_name": port_info.get("service", {}).get("name", ""),
                        "service_version": "",
                        "product": "",
                    })

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse Masscan JSON: {e}")

        return list(hosts_dict.values())

    # ═══════════════════════════════════════════════════════════
    # FR-01-02: Passive Network Listener
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def run_passive_listener(
        interface: Optional[str] = None,
        duration: int = 60,
    ) -> List[Dict[str, Any]]:
        """Sniff network traffic to detect new devices via ARP/DHCP.

        Args:
            interface: Network interface to listen on (None = default)
            duration: Duration in seconds to listen

        Returns:
            List of discovered device dictionaries
        """
        try:
            from scapy.all import sniff, ARP, DHCP, Ether

            discovered = {}

            def packet_handler(pkt):
                """Process ARP and DHCP packets to discover devices."""
                ip = None
                mac = None

                # ARP packets
                if ARP in pkt:
                    if pkt[ARP].op == 2:  # ARP reply (is-at)
                        ip = pkt[ARP].psrc
                        mac = pkt[ARP].hwsrc
                    elif pkt[ARP].op == 1:  # ARP request (who-has)
                        ip = pkt[ARP].psrc
                        mac = pkt[ARP].hwsrc

                # Ethernet source
                elif Ether in pkt:
                    mac = pkt[Ether].src
                    if hasattr(pkt, "payload") and hasattr(pkt.payload, "src"):
                        ip = str(pkt.payload.src)

                if ip and mac and ip != "0.0.0.0":
                    if ip not in discovered:
                        discovered[ip] = {
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": None,
                            "os_info": {},
                            "hardware_vendor": None,
                            "ports": [],
                            "last_scanned": datetime.now(timezone.utc).isoformat(),
                            "scan_source": "passive",
                        }

            logger.info(f"Starting passive listener for {duration}s on interface={interface}")

            sniff_kwargs = {
                "prn": packet_handler,
                "timeout": duration,
                "store": 0,
                "filter": "arp or udp port 67 or udp port 68",
            }
            if interface:
                sniff_kwargs["iface"] = interface

            sniff(**sniff_kwargs)

            logger.info(f"Passive listener discovered {len(discovered)} devices")
            return list(discovered.values())

        except ImportError:
            logger.error("Scapy not available for passive scanning")
            return []
        except Exception as e:
            logger.error(f"Passive listener error: {e}")
            return []
