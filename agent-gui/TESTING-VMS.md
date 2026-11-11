# Testing a new agent build on the VMs

Every time the agent's code changes: build on the PC, update the Windows VM and the Ubuntu VM, check
them on the staging dashboard. Each machine takes one command. The scripts are in `packaging/dev/`.

| Machine | Gets the build from | Agent runs as |
|---|---|---|
| Development PC | `agent-gui\dist` (it builds it) | service `EagleEyeAgent` (the installer) |
| Windows VM | the VMware shared folder `\\vmware-host\Shared Folders\agent-gui` | service `EagleEyeAgent` (the installer) |
| Ubuntu VM (`user@192.168.36.50`) | `scp` from the PC | systemd `eagleeye-agent`, code in `/opt/eagleeye-dev` |

The version number stays 0.1.0 while developing (every agent, the phone app too; it is renumbered at release), so tell builds apart by the
time the scripts print ("built 2026-11-09 14:05") and the start line in the agent's log.

## One-time setup

**PC**
- `agent-gui\.venv` with the requirements, and Inno Setup 6 (for the Windows installer).
- So `scp` stops asking for the VM's password: create a key once and copy it to the VM:
  ```powershell
  ssh-keygen -t ed25519                     # Enter at every question
  type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh user@192.168.36.50 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
  ```

**Staging dashboard**
- Agents → Install → **New install code** (staging tenant, 90 days): one code connects every test machine,
  each as an agent of its own, and reinstalls keep their agent. Save it in a file on each VM:
  `C:\eagleeye-code.txt` (Windows) and `~/code.txt` (Ubuntu). Only needed for a first install or after a purge.

**SBOM tools for the VMs** (Syft and Grype). Download them on the PC: `github.com` has answered 504 on this
network (from the VMs too, so their own downloads fail), while GitHub's API works. The script downloads
through the API, checks each file against the release's checksums, and puts them in `agent-gui\dist\sbom-tools`:
```powershell
.\packaging\dev\fetch-sbom-tools.ps1 -Ubuntu user@192.168.36.50      # -Ubuntu also copies the Linux ones to the VM
```

**Windows VM**
- The shared folder `agent-gui` (VMware → Settings → Options → Shared Folders → `C:\FYP\UMEagleEye2.0\agent-gui`).
- SBOM tools where the agent service can see them (administrator PowerShell):
  ```powershell
  New-Item -ItemType Directory -Force 'C:\Program Files\syft','C:\Program Files\grype' | Out-Null
  Copy-Item '\\vmware-host\Shared Folders\agent-gui\dist\sbom-tools\windows\syft.exe' 'C:\Program Files\syft\'
  Copy-Item '\\vmware-host\Shared Folders\agent-gui\dist\sbom-tools\windows\grype.exe' 'C:\Program Files\grype\'
  ```

**Ubuntu VM**
- `python3 --version` must be 3.12 or later (Ubuntu 24.04).
- SBOM tools: `sudo install -m 755 ~/syft ~/grype /usr/local/bin/` (Grype's database needs about 6 GB free).

On its first SBOM, Grype downloads its vulnerability database (about 3 GB) from Anchore's own servers, not
GitHub, so the VMs still need internet (and DNS) for the CVE check. The agent service keeps it in its own folder:
`/var/lib/eagleeye/grype-db` (Ubuntu), `C:\ProgramData\EagleEye\grype-db` (Windows); a database Grype had
already downloaded in its default place is moved there once. The Setup page shows its size and date. To
update or check it by hand, use that same folder (otherwise Grype makes another 3 GB copy for your account):
```bash
sudo GRYPE_DB_CACHE_DIR=/var/lib/eagleeye/grype-db grype db update
```
```powershell
$env:GRYPE_DB_CACHE_DIR = 'C:\ProgramData\EagleEye\grype-db'; & 'C:\Program Files\grype\grype.exe' db update
```

## Every round

**1. PC** (PowerShell in `C:\FYP\UMEagleEye2.0\agent-gui`): runs the tests, builds the installer and the
Linux package, copies the package and the update script to the Ubuntu VM.
```powershell
.\packaging\dev\build-test.ps1 -Ubuntu user@192.168.36.50
```
Add `-SkipInstaller` when only the Linux side changed (faster).

**2. Windows VM** (administrator PowerShell). The script comes from the shared folder, so it runs with
`-ExecutionPolicy Bypass`:
```powershell
powershell -ExecutionPolicy Bypass -File "\\vmware-host\Shared Folders\agent-gui\packaging\dev\update-windows-vm.ps1"
```
First install, or after a purge: add `-CodeFile C:\eagleeye-code.txt`. It ends with the service status
and the last lines of `C:\ProgramData\EagleEye\logs\agent.log`.

**3. Ubuntu VM:**
```bash
sudo bash ~/update-ubuntu-vm.sh ~/eagleeye-agent-0.1.0.tar.gz
```
First install, or after a purge: add `--code-file ~/code.txt`. It ends with the service status and the last
lines of `/var/lib/eagleeye/logs/agent.log`.

**4. Your PC's own agent** (when you want it on the new build too), administrator PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File C:\FYP\UMEagleEye2.0\agent-gui\packaging\dev\update-windows-vm.ps1 -Dist C:\FYP\UMEagleEye2.0\agent-gui\dist
```

## What to check

| Where | Check |
|---|---|
| Each machine (script output) | `service status` says running, "last heartbeat ... (ok)"; no errors in the log lines |
| Staging → Agents tab | Each machine Online, seen within a minute; Roles as set |
| The agent's panel | No "applying..." after a minute; no SBOM-tools warning (unless you are testing it) |
| The agent window (Windows) | Status: Running; Setup → Tools: Syft and Grype "Found" (as the service sees them) |
| A settings change | Change one in the agent's panel (e.g. Scan depth): within a minute its log says "Applied the administrator's settings (... changed: scan_ports)" |
| Jobs | New scan of the VM's network; the asset's **Collect inventory** and **Run SBOM scan**: each finishes, and shows on Discovery / the asset page |
| What you changed | The scenario of the change itself (write it down before you start) |

## A clean install (now and then, and before a release)

```powershell
# Windows VM
powershell -ExecutionPolicy Bypass -File "\\vmware-host\Shared Folders\agent-gui\packaging\dev\update-windows-vm.ps1" -Purge -CodeFile C:\eagleeye-code.txt
```
```bash
# Ubuntu VM
sudo bash ~/update-ubuntu-vm.sh --purge
sudo bash ~/update-ubuntu-vm.sh ~/eagleeye-agent-0.1.0.tar.gz --code-file ~/code.txt
```
A purge removes the agent and its settings; with the install code it registers as a NEW agent. Delete the old
one on the Agents tab (its panel → Delete).

## Afterwards

- Delete what your PC reported to staging while testing, if it should not stay there (its asset on the
  Inventory page; its agent on the Agents tab if you made a new one).
- Keep the VMs' agents if you will test again; delete them on the Agents tab otherwise.

## When something fails

| Symptom | Look at |
|---|---|
| Setup exit code 10 | Installed but not connected: the code expired, was withdrawn or is used up, or no network. `%TEMP%\eagleeye-setup.log` |
| "running scripts is disabled" | Start it with `powershell -ExecutionPolicy Bypass -File ...` as above |
| Ubuntu service not running | `journalctl -u eagleeye-agent -n 50`; `cd /opt/eagleeye-dev && sudo python3 -m eagleeye service status` |
| Heartbeat failed | The log's error; the API URL (staging), the VM's DNS (NAT network adapter connected) |
| Daily SBOM skipped | The log names what is missing and where to put it; the window's Setup page shows what the service sees |
