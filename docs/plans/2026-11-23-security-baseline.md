# Security baseline (CIS-based, 95% target): plan

Status: **proposal, no code yet** (23 Nov 2026). Asked for by the stakeholders on 23 Nov: "baseline, follow
security benchmark", "target area around 95%", "be fair for Linux and Windows", "OpenSCAP".

## What exists today

`workers/src/lib/endpointPosture.ts` scores a computer 0-100 from **10 weighted checks** the inventory already
carries: updates 20, firewall 15, antivirus 15, disk encryption 15, UAC 10, SMBv1 10, Secure Boot 5, TPM 5,
RDP 5, local admins 5. It is Windows-shaped: on Linux UAC is always unknown, TPM is guessed from `/dev/tpm*`,
"updates" is only the age of the last `apt`/`dnf` run (not whether security updates are waiting), and there is
no Linux equivalent of the Windows missing-patch alert (`os_patch_missing`, MSRC).

## What we build

### 1. Thirty checks per OS, in the same eight areas

Each check cites its CIS Benchmark recommendation (Windows 11 Enterprise; Ubuntu 24.04 LTS / RHEL family,
Level 1) with our own wording. The agent reports the **raw values**; the server decides pass/fail
(`lib/baseline.ts`, versioned like `POSTURE_MODEL`), so a rule can be corrected without an agent release.

| Area | Windows (30) | Linux (30) |
|---|---|---|
| Updates | last update ≤ 30 days · automatic updates on · OS version still supported | last update ≤ 30 days · **no security updates waiting** (new) · automatic security updates on (unattended-upgrades / dnf-automatic) |
| Accounts and passwords | min length ≥ 14 · complexity on · max age ≤ 365 · lockout after ≤ 5 tries · lockout ≥ 15 min · Guest disabled · built-in Administrator renamed/disabled · ≤ 3 local admins | min length ≥ 14 (pwquality) · lockout after ≤ 5 tries (faillock) · max age ≤ 365 · no empty passwords · only root has UID 0 · root password locked · ≤ 3 sudo users |
| Firewall | on in every profile · inbound blocked by default | active (ufw / firewalld / nftables) · incoming denied by default |
| Disk and boot | BitLocker on the OS drive · Secure Boot · TPM ready | disk encryption (LUKS) · Secure Boot · boot loader config readable by root only |
| Remote access and network | RDP off or NLA required · SMBv1 off · SMB signing required · LLMNR off · WinRM Basic auth off | SSH root login off · SSH empty passwords off · SSH max auth tries ≤ 4 · no telnet/rsh/tftp servers · SMBv1 off (Samba) · no VNC/xrdp |
| System hardening | UAC on · UAC prompts on the secure desktop · AutoRun off · PowerShell script block logging on | ASLR full · IP forwarding off (n/a on a router) · ICMP redirects ignored · AppArmor/SELinux enforcing |
| Malware and integrity | antivirus on · signatures ≤ 7 days old · SmartScreen on | file integrity tool installed (AIDE) · `/etc/shadow` 0640 or stricter |
| Logging and time | logon events audited (success + failure) · Security log ≥ 196,608 KB | auditd running · logs kept across reboots · time sync active |

The exact list is fixed in step 1 against the benchmark PDFs; the rule is **the same count per OS, in the same
areas**, so a Linux server and a Windows PC are judged equally hard. macOS follows once a real Mac is
available; phones keep their own four checks.

### 2. How the percentage is worked out

- Each check is **pass**, **fail**, **not applicable** (IP forwarding on a router) or **not readable** (needs
  root/Administrator, or the OS does not report it).
- **Device %** = passed ÷ (passed + failed). Not applicable and not readable are left out and listed, never
  counted as passes (the same rule as today's score). A device with fewer than 24 of 30 readable is
  *not assessed* rather than given a flattering number.
- **Organisation %** = all passed checks ÷ all judged checks across assessed devices, shown with
  **"N of M devices at target"**, so one bad server is not hidden by many good laptops.
- **Target**: a tenant setting, default **95%**, edited on the Alert rules page next to the fix-time targets.

### 3. Where it shows

- **Asset page**: a *Security baseline* card: the %, then failed checks first, each with what was found, what
  is expected, the CIS reference and how to fix it.
- **Dashboard**: a *Baseline* tile (organisation %, target, devices at target), linking to a device list
  sorted by %.
- **Reports and Week by week**: organisation % and devices at target as weekly measures.
- **Alerts**: one *Below baseline* alert per device under target (like the one Windows patch alert per machine):
  tier 3, medium, high under 80%; it lists the failed checks and closes when the device reaches target.
- **Linux security updates waiting**: an alert like the Windows patch alert: high, one per machine, with
  the number of updates (`apt-check` / `dnf updateinfo --security`).

### 4. OpenSCAP on Linux (optional)

When `oscap` and the SCAP Security Guide content are installed, the agent can run the CIS Level 1 profile
weekly (off by default; it takes minutes) and upload the result per rule. It is shown as its own section on the
asset page ("OpenSCAP: 212 of 240 rules pass") and does **not** replace our 30 checks, because Windows has no
OpenSCAP and the comparison must stay fair.

## Order of work

1. **Checks**: final list with CIS references; collectors on both OSes (`windows_inventory.ps1`, `linux.py`),
   `lib/baseline.ts` with tests from recorded outputs of the PC and both VMs. Ships to agents through the new
   dashboard updates.
2. **Score and display**: migration (asset baseline columns, tenant target), asset card, dashboard tile,
   reports, weekly measures, *Below baseline* alert.
3. **Linux security updates** check and alert.
4. **OpenSCAP** import.
5. **Evaluation**: run CIS-CAT Lite (CIS's free assessor) on the Windows VM and the Ubuntu VM and measure how
   often our verdict agrees with it, check by check; record it with the AP2 evaluation files.

## Decisions needed

1. **Beside or instead of the 10-check device score?** Recommended: beside for now (the posture history stays
   comparable), and fold the 10 checks into the baseline once it has run for a few weeks.
2. **The below-target alert**: one per device as above (recommended), or no alert, only the dashboard figure.
3. **One profile per OS** (recommended for now), or separate server and workstation profiles as CIS has.
4. **OpenSCAP** opt-in per agent and weekly (recommended), or not at all.

## Not claimed

UMEagleEye does not claim CIS certification (that needs CIS membership and CIS-CAT Pro). The benchmarks are
cited by recommendation number; their text is not copied into the product.
