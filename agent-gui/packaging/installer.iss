; Inno Setup script for the EagleEye Agent (Windows).
; Built by packaging/build.ps1 after PyInstaller has produced dist/EagleEyeAgent/.
; Inno Setup 6: https://jrsoftware.org/isinfo.php
;
; User experience:
;  - a short "before you install" page (what to have ready, what happens, what is never
;    collected) instead of a wall of licence text; the third-party notices are installed
;    and linked from the Start menu;
;  - starting at sign-in is ON by default (the agent is meant to keep running), as an
;    elevated logon task so passive listening and the full inventory work without a UAC
;    prompt each time; unticking it on an upgrade removes the task;
;  - "Open EagleEye Agent now" starts it through that task, so the first run already has
;    Administrator rights; without the task it starts as the signed-in user;
;  - an upgrade closes the running agent first and keeps its settings.

#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif

[Setup]
AppId={{6B2E3C7A-6E4D-4F37-9C1E-EA6E7E0A2B10}
AppName=EagleEye Agent
AppVersion={#AppVersion}
AppVerName=EagleEye Agent {#AppVersion}
AppPublisher=UMEagleEye
AppPublisherURL=https://umeagleeye.csnet.my
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\EagleEye Agent
DefaultGroupName=EagleEye Agent
DisableProgramGroupPage=yes
DisableReadyPage=yes
OutputDir=..\dist
OutputBaseFilename=EagleEyeAgent-Setup-{#AppVersion}
SetupIconFile=..\build\eagleeye.ico
UninstallDisplayIcon={app}\EagleEyeAgent.exe
UninstallDisplayName=EagleEye Agent
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
InfoBeforeFile=BEFORE-YOU-INSTALL.txt
; Close a running agent (tray app) before replacing its files; it is started again from
; the finish page.
CloseApplications=yes
CloseApplicationsFilter=EagleEyeAgent.exe,eagleeye.exe
RestartApplications=no

[Tasks]
Name: "autostart"; Description: "Start EagleEye Agent when I sign in (recommended: it keeps reporting, with the Administrator rights it needs)"
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\dist\EagleEyeAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\EagleEye Agent"; Filename: "{app}\EagleEyeAgent.exe"
Name: "{group}\Third-party notices"; Filename: "{app}\_internal\THIRD-PARTY-NOTICES.txt"
Name: "{group}\Uninstall EagleEye Agent"; Filename: "{uninstallexe}"
Name: "{autodesktop}\EagleEye Agent"; Filename: "{app}\EagleEyeAgent.exe"; Tasks: desktopicon

[Run]
; A logon task with highest privileges starts the agent elevated without a UAC prompt at each sign-in.
Filename: "{sys}\schtasks.exe"; \
  Parameters: "/Create /F /TN ""EagleEye Agent"" /TR ""\""{app}\EagleEyeAgent.exe\"" --minimized"" /SC ONLOGON /RL HIGHEST /IT"; \
  Flags: runhidden; Tasks: autostart
; Unticked on an upgrade: remove the task an earlier install created (no error if there is none).
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""EagleEye Agent"""; \
  Flags: runhidden; Tasks: not autostart
; Finish page. With the task: start through it, so the agent runs as Administrator right away
; (a first run without settings still opens its window). Without it: as the signed-in user.
Filename: "{sys}\schtasks.exe"; Parameters: "/Run /TN ""EagleEye Agent"""; \
  Description: "Open EagleEye Agent now"; Flags: postinstall nowait runhidden skipifsilent; Tasks: autostart
Filename: "{app}\EagleEyeAgent.exe"; Description: "Open EagleEye Agent now"; \
  Flags: postinstall nowait skipifsilent runasoriginaluser; Tasks: not autostart

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""EagleEye Agent"""; Flags: runhidden; RunOnceId: "RemoveTask"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM EagleEyeAgent.exe /F"; Flags: runhidden; RunOnceId: "StopAgent"

[Messages]
WelcomeLabel2=This installs [name/ver] on your computer.%n%nIt connects this computer to your organisation's EagleEye dashboard. Have the API URL, agent ID and API key from your IT administrator ready.
FinishedHeadingLabel=EagleEye Agent is installed
FinishedLabel=Next: the agent shows what it collects, then asks for the API URL, agent ID and API key from your IT administrator. Paste them, press Test connection, then Save.%n%nAfterwards it runs in the system tray (the blue eye icon next to the clock).
FinishedLabelNoIcons=Next: the agent shows what it collects, then asks for the API URL, agent ID and API key from your IT administrator. Paste them, press Test connection, then Save.%n%nAfterwards it runs in the system tray (the blue eye icon next to the clock).
