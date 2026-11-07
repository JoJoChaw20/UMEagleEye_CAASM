"""Which TCP ports the own engine scans, in tiers chosen per agent (Settings.scan_ports).

base      the 13 ports the agent has always scanned (the Nmap stage's list without TCP 161:
          SNMP is UDP, so a TCP check of 161 always found it closed)
consumer  base + what phones, TVs, media players, printers, cameras and smart-home devices
          listen on
wide      consumer + common server, remote-access, directory, container and industrial ports,
          for networks with servers (company networks)

Service names are the IANA registry names, used until a probe identifies the service.
"""

from __future__ import annotations

BASE_PORTS: tuple[int, ...] = (22, 23, 80, 139, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379, 27017)

_CONSUMER_EXTRA = (
    53, 515, 554, 631, 1883, 2869, 3689, 5000, 5555, 6466, 6467, 7000, 7100,
    8000, 8008, 8009, 8060, 8883, 9000, 9100, 49152, 49153, 62078,
)

_WIDE_EXTRA = (
    21, 25, 88, 102, 110, 111, 135, 143, 389, 465, 502, 587, 593, 636, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3128, 3268, 4443, 4840, 5060,
    5601, 5900, 5901, 5985, 5986, 6000, 6443, 7001, 8001, 8081, 8088, 8090, 8181,
    8888, 9001, 9090, 9200, 9443, 10000, 10250, 11211, 15672, 20000, 44818, 50000,
)


def _unique(*groups: tuple[int, ...]) -> tuple[int, ...]:
    seen: dict[int, None] = {}
    for group in groups:
        for port in group:
            seen.setdefault(port, None)
    return tuple(seen)


CONSUMER_PORTS = _unique(BASE_PORTS, _CONSUMER_EXTRA)
WIDE_PORTS = _unique(CONSUMER_PORTS, _WIDE_EXTRA)
TIERS = {"base": BASE_PORTS, "consumer": CONSUMER_PORTS, "wide": WIDE_PORTS}

# Ports asked when no ARP/ping answer says whether a routed host is up (a refusal counts too).
PING_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389)

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 88: "kerberos",
    102: "iso-tsap", 110: "pop3", 111: "sunrpc", 135: "epmap", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "submissions", 502: "mbap", 515: "printer",
    554: "rtsp", 587: "submission", 593: "http-rpc-epmap", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1521: "ncube-lm", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 2375: "docker", 2376: "docker-s", 2869: "icslap", 3000: "hbci", 3128: "ndl-aas",
    3268: "msft-gc", 3306: "mysql", 3389: "ms-wbt-server", 3689: "daap", 4443: "pharos",
    4840: "opcua-tcp", 5000: "commplex-main", 5060: "sip", 5432: "postgresql", 5555: "personal-agent",
    5601: "esmagent", 5900: "rfb", 5901: "rfb", 5985: "wsman", 5986: "wsmans", 6000: "x11",
    6379: "redis", 6443: "sun-sr-https", 6466: "androidtv-remote", 6467: "androidtv-remote",
    7000: "afs3-fileserver", 7001: "afs3-callback", 7100: "font-service", 8000: "irdmi",
    8001: "vcom-tunnel", 8008: "http-alt", 8009: "ajp13", 8060: "aero", 8080: "http-alt",
    8081: "sunproxyadmin", 8088: "radan-http", 8090: "opsmessaging", 8181: "intermapper",
    8443: "pcsync-https", 8883: "secure-mqtt", 8888: "ddi-tcp-1", 9000: "cslistener",
    9001: "etlservicemgr", 9090: "websm", 9100: "pdl-datastream", 9200: "wap-wsp", 9443: "tungsten-https",
    10000: "ndmp", 10250: "kubelet", 11211: "memcache", 15672: "rabbitmq-mgmt", 20000: "dnp",
    27017: "mongodb", 44818: "EtherNet-IP-2", 49152: "upnp", 49153: "upnp", 50000: "ibm-db2",
    62078: "iphone-sync",
}


def ports_for(tier: str) -> tuple[int, ...]:
    try:
        return TIERS[tier]
    except KeyError:
        raise ValueError(f"unknown port tier {tier!r}: expected one of {', '.join(TIERS)}") from None


def service_name(port: int) -> str:
    return SERVICE_NAMES.get(port, "")
