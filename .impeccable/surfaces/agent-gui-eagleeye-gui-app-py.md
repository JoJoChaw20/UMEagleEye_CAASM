---
version: 1
slug: "agent-gui-eagleeye-gui-app-py"
primary_target: "agent-gui/eagleeye/gui/app.py"
related_targets: ["agent-gui/eagleeye/gui/pages.py","agent-gui/eagleeye/gui/theme.py","agent-gui/eagleeye/gui/widgets.py","agent-gui/eagleeye/gui/consent.py"]
---

# EagleEye Agent desktop app (PySide6)

Scope: the Windows agent app (EagleEyeAgent.exe), every window: main window (Status, Log, Settings, Privacy, Dependencies; Schedules when enabled), the first-run notice, dialogs, tray menu. Mode: Operate.

Audience and task: the person at the monitored computer (often the same IT admin as the dashboard) sets the agent up once (paste connection code, accept notice), then glances at it: is it running, did the heartbeat go through, what is it scanning, did the last run fail. Rarely: change privacy choices, install Nmap/Npcap, read the log.

Constraints: same visual world as the dashboard (DESIGN.md), translated to Qt; dark, light and system themes; Qt Fusion + QSS + painted widgets; no web view. All behaviour, copy facts and tests of the old app kept.

## Direction contract
THESIS: the agent is the dashboard's field unit, so it wears the dashboard's shell: navy rail with the logo and a circuit-bus nav, a sunken header carrying the live state and Start/Stop, solid panels with ring-node headings. Refuses the stock Qt look (group boxes, OS-blue nav list).
OWN-WORLD: DESIGN.md tokens verbatim (rail #08101F, ink/paper neutrals, eagle blues, cyan only for live), Chakra Petch headings, Geist UI, Geist Mono for IDs/IPs/paths, 6px controls, 10px panels, 1px lines, Lucide icons.
STORY: open the app, read the header (dot + Running + heartbeat time) in one glance; Status shows Now (activity + trace loader + run buttons), Connection, Recent activity; setup pages keep Save in a sticky footer.
FIRST VIEWPORT: rail 240px left (logo 54px, groups Agent / Setup, host tile at foot); header 64px (live dot, state, detail, theme switch, Start/Stop, Quit); content: page title + 44px trace, description, notice line when not set up or stopped, then panels.
FORM: extension of the established dashboard world (DESIGN.md) to a new surface. No concept roll was owed or run: new-work.md section 3 says "Never run the script for a local extension or a precisely specified narrow request; shape those directly." seed: none (no roll: extension).
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
