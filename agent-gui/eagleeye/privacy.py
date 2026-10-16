"""The data-collection notice shown before the agent first runs (PDPA 2010: notice
and choice). Bump CONSENT_VERSION whenever what is collected changes, so the
notice is shown again."""

from __future__ import annotations

CONSENT_VERSION = 2     # 2: software packages (SBOM) added

NOTICE_TITLE = "What this agent collects"

NOTICE_HTML = """
<p>The EagleEye agent helps your organisation keep an inventory of its devices and find
security weaknesses. It sends what it finds over HTTPS to your organisation's own
EagleEye server only, where your organisation's administrators can see it. Nothing is
sent to anyone else.</p>

<h3>Network discovery</h3>
<p>When an administrator starts a scan (or a schedule you set runs), the agent scans the
network range you choose and records the devices it finds: IP and MAC addresses, device
names, open ports, the services behind them, and an operating-system guess.</p>

<h3>Passive listening (optional, off by default)</h3>
<p>Reads only broadcast discovery messages (ARP, mDNS, NetBIOS, DHCP) to learn device
names and addresses. It never reads the contents of anyone's traffic.</p>

<h3>This computer's inventory (optional)</h3>
<p>Hardware model and serial number, operating system and patches, security settings
(firewall, antivirus, disk encryption, Secure Boot, TPM, UAC, remote desktop, SMBv1), the
<b>number</b> of local administrator accounts, network interfaces, network-reachable
listening ports with the program behind them, and software installed for all users.</p>
<p>Two items identify a person more directly and are <b>off unless you switch them on</b>:
software one user installed only for themselves, and the names of the administrator
accounts.</p>

<h3>Software packages (SBOM, on by default)</h3>
<p>Once a day, and when an administrator asks, the agent lists the software packages
installed in the folders programs install to (on Windows: Program Files and ProgramData;
on Linux: the system, not the home folders), plus any folder you add, and checks them
for known vulnerabilities on this computer. It sends each package's name, version,
licence and package identifier, and the vulnerabilities found. It reads package
records, not your documents, and sends no file contents or file paths.</p>

<h3>Never collected</h3>
<p>Files or documents, browsing history, passwords or other credentials, keystrokes,
screenshots, email or messages, location, or the contents of network traffic.</p>

<h3>Your choices</h3>
<p>You can change these choices at any time on the Privacy page, preview exactly what
would be sent, or stop the agent. An administrator can delete this computer's inventory
from the server with <i>Clear inventory</i> on its asset page. Only the latest inventory
is kept; each collection replaces the previous one.</p>
"""
