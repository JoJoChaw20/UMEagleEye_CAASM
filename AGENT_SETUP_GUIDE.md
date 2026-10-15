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
2. runs the network scans you start from **Discovery** (Nmap, or a simpler built-in scan when Nmap is missing);
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
4. Send the installer, the connection code and the install guide link to the user over a **private** channel.
   Anyone with the code can report as this agent.

Lost the code, or sent it to the wrong place? Choose **New connection code** (the key icon) on the agent's row.
The old key stops working at once; paste the new code into the agent.

---

## 2. Install on Windows

1. Run `EagleEyeAgent-Setup-<version>.exe` (it needs administrator rights). Keep
   **Start EagleEye Agent when I sign in** ticked: the agent then starts with the rights it needs for passive
   listening and the full security checks, without a prompt each time.
2. On first start the agent shows what it collects. The personal-data options are off by default.
3. In **Settings**, paste the code into **Connection code**, choose **Use code**, then **Test connection** and
   **Save**. Saving starts the agent.
4. On **Dependencies**, install Nmap (and Npcap from the Nmap installer). They are free but cannot be bundled with
   the agent because of their licences; the agent downloads the official, signed installers.

Updating: run the newer installer over the old one. It closes the running agent and keeps its settings.

---

## 3. Install on Linux (servers, no desktop)

```bash
cd agent-gui
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m eagleeye config init --connection-code '<code from the Agents page>'
sudo .venv/bin/python -m eagleeye run --passive     # root for passive listening; omit --passive otherwise
```

Install Nmap with the system package manager (`sudo apt install nmap`). Run `python -m eagleeye --help` for every
option; `python -m eagleeye inventory` shows what would be sent without sending it.

---

## 4. Check it works

On the **Agents** page the agent shows **Online**, and after its first inventory the **Computer** column links to
the computer's page in Inventory, with an agent-confirmed device type and a posture score.

In the agent, the **Status** page shows *Running*, a recent heartbeat and, with passive listening on, the network
it listens on (for example *Wi-Fi (192.168.1.20)*).

| Problem | What to do |
|---|---|
| Agent stays **Offline** | Open the agent: if it says *Stopped*, choose **Start**; check Settings > Test connection |
| *The server rejected the agent ID or API key* | The key was rotated or mistyped: issue a new connection code |
| *needs Administrator* on passive listening | Start it through the sign-in task (sign out and in) or Dependencies > **Restart as Administrator** |
| Passive listening on the wrong network | Leave **Network interface** empty in Settings (automatic follows the network the computer uses) |

---

## Retired: the 1.x agent and the bridge

The original agent (`eagleeye_agent.py`, version 1.x) and its bridge relay for isolated networks were retired in
agent 2.0.2. Their keys were revoked, so 1.x agents can no longer connect; they are listed under **Retired agents**
with their Discovery history, which stays until you delete the agent. Replace each one by installing the current
agent on that computer. The old code remains in git history under the `legacy-archive` tag.
