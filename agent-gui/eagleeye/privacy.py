"""The data-collection notice shown before the agent first runs (PDPA 2010: notice).
Bump CONSENT_VERSION whenever what is collected changes, so the notice is shown again.
Since 2.4.0 what is collected is the organisation's decision (agent settings set on the
dashboard), as with any company device-management tool; the notice says what it is."""

from __future__ import annotations

CONSENT_VERSION = 6     # 2: software packages (SBOM) added; 3: SSDP/UPnP device announcements (passive);
                        # 4: automatic scan of newly heard devices (tenant setting), dashboard inventory requests;
                        # 5: the administrator sets what is collected from the dashboard (agent settings);
                        # 6: the inventory always includes software users installed for themselves, and
                        #    administrator account names are never sent

NOTICE_TITLE = "What this agent collects"

NOTICE_HTML = """
<p>The EagleEye agent helps your organisation keep an inventory of its devices and find
security weaknesses. It sends what it finds over HTTPS to your organisation's own
EagleEye server only, where your organisation's administrators can see it. Nothing is
sent to anyone else.</p>

<h3>Network discovery</h3>
<p>When an administrator starts a scan from the dashboard, the agent scans the chosen network
range and records the devices it finds: IP and MAC addresses, device names, open ports, the
services behind them, and an operating-system guess.</p>
<p>If your organisation has turned it on, a device that passive listening hears for the
first time is scanned the same way a few minutes later, on that device's own address only,
so administrators can see what it is.</p>

<h3>Passive listening (optional, off by default)</h3>
<p>Reads only broadcast discovery messages (ARP, mDNS, NetBIOS, DHCP, SSDP/UPnP) to learn device
names, addresses and what kind of device each one says it is. It never reads the contents of anyone's traffic.</p>

<h3>This computer's inventory (on by default)</h3>
<p>Hardware model and serial number, operating system and patches, security settings
(firewall, antivirus, disk encryption, Secure Boot, TPM, UAC, remote desktop, SMBv1), the
<b>number</b> of local administrator accounts (never their names), network interfaces,
network-reachable listening ports with the program behind them, and the installed software:
the programs installed for everyone and those each signed-in user installed for themselves
(name, version and publisher), because out-of-date programs are a common way in for attackers.</p>

<h3>Software packages (SBOM, on by default)</h3>
<p>Every day (only the folders that changed), once a week in full, and when you or an
administrator ask, the agent lists the software packages
installed in the folders programs install to (on Windows: Program Files and ProgramData;
on Linux: the system, not the home folders), plus any folder you add, and checks them
for known vulnerabilities on this computer. It sends each package's name, version,
licence and package identifier, and the vulnerabilities found. It reads package
records, not your documents, and sends no file contents or file paths.</p>

<h3>Never collected</h3>
<p>Files or documents, browsing history, passwords or other credentials, keystrokes,
screenshots, email or messages, location, or the contents of network traffic.</p>

<h3>Who decides</h3>
<p>Your organisation's administrator sets what this agent collects from the EagleEye
dashboard; the Privacy page shows them. They are not changed on this computer. You can preview exactly
what would be sent at any time. An administrator can ask for a fresh inventory from the
dashboard, and can delete this computer's inventory from the server with <i>Clear
inventory</i> on its asset page. Only the latest inventory is kept; each collection
replaces the previous one.</p>
"""
