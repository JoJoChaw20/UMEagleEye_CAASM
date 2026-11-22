"""Threat sightings: this computer contacting a domain or IP its organisation's threat
intelligence lists as bad (dashboard setting "Threat sightings", off by default).

The agent keeps a copy of the tenant's matchable bad domains and IPs (indicators.py, synced
from GET /sightings/indicators), and checks against it, on this computer:

  * the DNS answers this computer receives (dns.py; its own capture, which takes only DNS
    answers: the name looked up, the CNAME chain and the addresses it resolved to);
  * its outbound TCP connections, polled every 30 s (connections.py), with the program
    behind one looked up only when it matches;
  * the programs running on it, as file hashes (programs.py, every minute; each file hashed
    once while it stays the same), against the listed malware hashes.

Only matches leave the computer (recorder.py, POST /sightings); lookups, connections and
programs that match nothing are never stored or sent. monitor.py runs it all. The server re-checks every
hit and raises one alert per listed value (rule R7, workers/src/lib/sightings.ts).
"""

from .monitor import SightingsMonitor

__all__ = ["SightingsMonitor"]
