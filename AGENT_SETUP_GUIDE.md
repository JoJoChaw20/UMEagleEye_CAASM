# EagleEye Agent — rollout guide for IT administrators

This guide covers putting the **EagleEye Agent** (version 2.0.2 or later) on the computers of your organisation.
Staff who install it themselves follow the separate step-by-step *EagleEye Agent Install Guide*; send them a link
to it with the installer.

**Time per computer:** about 10 minutes
**Dashboard:** https://umeagleeye.csnet.my

---

## What the agent does

One agent runs on each computer. It:

1. sends a heartbeat every 30 seconds, so the dashboard shows it as online;
2. runs the network scans you start from the dashboard (**New scan**), with its own scan engine;
3. optionally listens passively for device announcements (ARP, mDNS, NetBIOS, DHCP) on the network the computer
   uses, and reports what it heard once an hour per agent in the Discovery log;
4. reports its own computer's **endpoint inventory** every 6 hours: hardware, Windows/Linux version and updates,
   firewall, antivirus, disk encryption, Secure Boot, TPM, listening services and installed software. The
   dashboard turns this into the computer's posture score.

It only makes outbound HTTPS calls to the EagleEye API and never listens for incoming connections. What it
collects and never collects is listed on its Privacy page and in `agent-gui/README.md`.

---

## 1. Register the agent

1. Open **Agents** in the dashboard and choose **Register agent**.
2. Give it a name you will recognise, for example *Finance laptop 03*.
3. Copy the **connection code** shown next. It contains the API URL, the agent ID and the API key, and it is
   shown **only once**. (The three values are also available separately under the code.)
4. Send the connection code and the install guide link to the user over a **private** channel.
   Anyone with the code can report as this agent. The installer itself holds no secrets: anyone signed in to the
   dashboard can get it with **Download agent** on the Agents page (also in the dialog that shows the code).

Lost the code, or sent it to the wrong place? Choose **New connection code** (the key icon) on the agent's row.
The old key stops working at once; paste the new code into the agent.

---

## 2. Install on Windows

1. Download it from the dashboard: Agents → Install → Windows (always the latest version), and run
   `EagleEyeAgent-Setup-<version>.exe` (it needs administrator rights). It installs the agent as a Windows service
   that starts with the computer.
2. Open **EagleEye Agent**, go to **Connection**, paste the code into **Connection code**, choose **Use code**, then
   **Test connection** and **Save**.
3. Everything the agent does (scanning, passive listening, inventory, SBOM) is set on the dashboard: Agents → the
   agent's panel, or Defaults for every agent. The agent's app only shows it. Nmap and Npcap are not needed.

Many computers (Intune, Group Policy, scripts): see the agent README, "Installing on many computers", or Agents →
Install → Windows.

Updating: run the newer installer over the old one. It keeps the agent's connection and settings.

### Publishing a new version (maintainers)

The dashboard's Agents → Install tab offers two downloads, each the **most recently uploaded** file of its kind
in the environment's R2 bucket under `agent-installer/` (not the highest version number, so a release renumbered
to 1.0 replaces the 2.x development builds):

| Download | File | Built with |
|---|---|---|
| Windows | `EagleEyeAgent-Setup-<version>.exe` | `agent-gui\packaging\build.ps1` (needs Inno Setup 6) |
| Linux and the network agent | `eagleeye-agent-<version>.tar.gz` | `python agent-gui\packaging\make_source.py` |

```powershell
cd workers
# staging; production: the same into umeagleeye-reports/agent-installer/
npx wrangler r2 object put umeagleeye-reports-staging/agent-installer/EagleEyeAgent-Setup-2.5.1.exe `
  --file ..\agent-gui\dist\EagleEyeAgent-Setup-2.5.1.exe --content-type application/vnd.microsoft.portable-executable --remote
npx wrangler r2 object put umeagleeye-reports-staging/agent-installer/eagleeye-agent-2.5.1.tar.gz `
  --file ..\agent-gui\dist\eagleeye-agent-2.5.1.tar.gz --content-type application/gzip --remote
```

Uploading the same file name again replaces it (and makes it the newest). To go back to an older build, upload it
again or delete the newer file (`npx wrangler r2 object delete <bucket>/agent-installer/<file> --remote`).

---

## 3. Install on Linux (servers, no desktop)

Download the Linux package from Agents → Install → Linux (`eagleeye-agent-<version>.tar.gz`; Python 3.12+ and
systemd needed), then, as root:

```bash
sudo tar xzf eagleeye-agent-<version>.tar.gz -C /opt && cd /opt/eagleeye-agent-<version>
sudo python3 -m venv .venv && sudo .venv/bin/pip install .
sudo .venv/bin/python -m eagleeye service enrol --connection-code 'EE...'   # or --connection-code-file
sudo .venv/bin/python -m eagleeye service install
sudo .venv/bin/python -m eagleeye service status
```

The network agent comes from the same package (its Docker image is built from it): see Agents → Install →
Network agent, or the agent README, "Network agent".

---

## 4. Check it works

On the **Agents** page the agent shows **Online**, and after its first inventory the **Computer** column links to
the computer's page in Inventory, with an agent-confirmed device type and a posture score.

In the agent, the **Status** page shows *Running*, a recent heartbeat and, with passive listening on, the network
it listens on (for example *Wi-Fi (192.168.1.20)*).

| Problem | What to do |
|---|---|
| Agent stays **Offline** | Open the agent: if it says *Stopped*, choose **Start**; check Connection > Test connection |
| *The server rejected the agent ID or API key* | The key was rotated or mistyped: issue a new connection code |
| *needs Administrator* on passive listening | The service runs with the rights it needs: check it is running (`Get-Service EagleEyeAgent`), or Setup > **Restart as Administrator** |
| Passive listening on the wrong network | The agent listens on the network the computer uses; check the Status page shows the right one |

---

## Retired: the 1.x agent and the bridge

The original agent (`eagleeye_agent.py`, version 1.x) and its bridge relay for isolated networks were retired in
agent 2.0.2. Their keys were revoked, so 1.x agents can no longer connect; they are listed under **Retired agents**
with their Discovery history, which stays until you delete the agent. Replace each one by installing the current
agent on that computer. The old code remains in git history under the `legacy-archive` tag.
