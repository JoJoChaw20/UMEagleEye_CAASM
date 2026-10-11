; Inno Setup script for the EagleEye Agent (Windows).
; Built by packaging/build.ps1 after PyInstaller has produced dist/EagleEyeAgent/.
; Inno Setup 6: https://jrsoftware.org/isinfo.php

#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif

[Setup]
AppId={{6B2E3C7A-6E4D-4F37-9C1E-EA6E7E0A2B10}
AppName=EagleEye Agent
AppVersion={#AppVersion}
AppPublisher=UMEagleEye
DefaultDirName={autopf}\EagleEye Agent
DefaultGroupName=EagleEye Agent
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=EagleEyeAgent-Setup-{#AppVersion}
SetupIconFile=..\build\eagleeye.ico
UninstallDisplayIcon={app}\EagleEyeAgent.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
InfoBeforeFile=THIRD-PARTY-NOTICES.txt

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start the agent when I sign in (as Administrator, needed for passive listening and the full inventory)"; Flags: unchecked

[Files]
Source: "..\dist\EagleEyeAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\EagleEye Agent"; Filename: "{app}\EagleEyeAgent.exe"
Name: "{group}\Uninstall EagleEye Agent"; Filename: "{uninstallexe}"
Name: "{autodesktop}\EagleEye Agent"; Filename: "{app}\EagleEyeAgent.exe"; Tasks: desktopicon

[Run]
; A logon task with highest privileges starts the agent elevated without a UAC prompt at each sign-in.
Filename: "{sys}\schtasks.exe"; \
  Parameters: "/Create /F /TN ""EagleEye Agent"" /TR ""\""{app}\EagleEyeAgent.exe\"" --minimized"" /SC ONLOGON /RL HIGHEST /IT"; \
  Flags: runhidden; Tasks: autostart
Filename: "{app}\EagleEyeAgent.exe"; Description: "Open EagleEye Agent now"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""EagleEye Agent"""; Flags: runhidden; RunOnceId: "RemoveTask"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM EagleEyeAgent.exe /F"; Flags: runhidden; RunOnceId: "StopAgent"

[Messages]
FinishedLabel=EagleEye Agent is installed. On first start it shows what it collects and asks for the server details from your dashboard's Agents page. Settings and the API key (kept in Windows Credential Manager) stay in your user profile after uninstalling; delete %APPDATA%\EagleEye and the "EagleEye Agent" entries in Windows Credential Manager to remove them.
