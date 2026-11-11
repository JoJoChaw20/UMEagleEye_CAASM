; Inno Setup script for the EagleEye Agent (Windows).
; Built by packaging/build.ps1 after PyInstaller has produced dist/EagleEyeAgent/.
; Inno Setup 6: https://jrsoftware.org/isinfo.php
;
; User experience:
;  - a short "before you install" page (what to have ready, what happens, what is never
;    collected) instead of a wall of licence text; the third-party notices are installed
;    and linked from the Start menu;
;  - the agent runs as the Windows service "EagleEye Agent" (2.5.0): started with Windows
;    as LocalSystem (Administrator rights for passive listening and the full inventory),
;    restarted after a failure, and not stopped by closing the app or signing out;
;    `eagleeye.exe service install` registers it and moves the installing user's
;    settings (and the key in their Credential Manager) into %ProgramData%\EagleEye;
;  - the app opens in the tray when anyone signs in (ON by default), as that user: it
;    shows the service and changes its settings after a Windows administrator prompt;
;  - an upgrade stops the service and closes the app first, keeps the settings, and
;    starts both again; it removes the elevated logon task earlier versions created;
;  - a company installs it silently (Intune, GPO, a script) and connects it at once:
;      EagleEyeAgent-Setup-<version>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;          /CONNECTIONCODEFILE=\\server\share\eagleeye-code.txt   (or /CONNECTIONCODE=<code>)
;    with a connection code (one computer) or an install code from the Agents page (many
;    computers: each registers an agent of its own). Add /MERGETASKS="!autostart" to leave
;    the tray app out. Exit code 10 = installed, but it could not connect (see the log:
;    /LOG="C:\Windows\Temp\eagleeye-setup.log").

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
Name: "autostart"; Description: "Show the EagleEye Agent status app in the tray when anyone signs in. The agent itself runs as a Windows service either way, from start-up to shutdown."
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\dist\EagleEyeAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\EagleEye Agent"; Filename: "{app}\EagleEyeAgent.exe"
Name: "{group}\Third-party notices"; Filename: "{app}\_internal\THIRD-PARTY-NOTICES.txt"
Name: "{group}\Uninstall EagleEye Agent"; Filename: "{uninstallexe}"
Name: "{autodesktop}\EagleEye Agent"; Filename: "{app}\EagleEyeAgent.exe"; Tasks: desktopicon

[Registry]
; The app (not the agent) at every sign-in, as that user, in the tray.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "EagleEye Agent"; \
  ValueData: """{app}\EagleEyeAgent.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "EagleEye Agent"; \
  Flags: deletevalue; Tasks: not autostart

[Run]
; Earlier versions started the app elevated through a logon task; the service replaces it.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""EagleEye Agent"""; Flags: runhidden
; Register (or update) the service, move this user's settings into it, and start it.
Filename: "{app}\eagleeye.exe"; Parameters: "service install"; Flags: runhidden; \
  StatusMsg: "Installing and starting the EagleEye Agent service..."
Filename: "{app}\EagleEyeAgent.exe"; Description: "Open EagleEye Agent now"; \
  Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
; The settings in %ProgramData%\EagleEye are kept (a reinstall finds them);
; `eagleeye.exe service uninstall --purge` removes them too.
Filename: "{app}\eagleeye.exe"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "RemoveService"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""EagleEye Agent"""; Flags: runhidden; RunOnceId: "RemoveTask"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM EagleEyeAgent.exe /F"; Flags: runhidden; RunOnceId: "StopAgent"

[Code]
var
  EnrolFailed: Boolean;
  CodeFileName: String;

function HasCode: Boolean;
begin
  Result := (ExpandConstant('{param:CONNECTIONCODE|}') <> '') or (ExpandConstant('{param:CONNECTIONCODEFILE|}') <> '');
end;

// The code goes to the agent in a file, never on its command line (process lists, logs);
// one given with /CONNECTIONCODE= is written to Setup's own temporary folder, removed at the end.
function CodeFile: String;
begin
  if CodeFileName = '' then
  begin
    CodeFileName := ExpandConstant('{param:CONNECTIONCODEFILE|}');
    if CodeFileName = '' then
    begin
      CodeFileName := ExpandConstant('{tmp}\connection-code.txt');
      SaveStringToFile(CodeFileName, ExpandConstant('{param:CONNECTIONCODE|}'), False);
    end;
  end;
  Result := CodeFileName;
end;

// Connect the service when a code was given (`eagleeye.exe service enrol`). Its order with the
// [Run] section does not matter: `service install` keeps settings that already exist, and a
// running service is told to reload them.
procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if (CurStep = ssPostInstall) and HasCode then
  begin
    WizardForm.StatusLabel.Caption := 'Connecting the agent to your EagleEye dashboard...';
    if (not Exec(ExpandConstant('{app}\eagleeye.exe'), 'service enrol --connection-code-file "' + CodeFile + '"', '',
                 SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
    begin
      EnrolFailed := True;
      Log('eagleeye.exe service enrol failed, exit code ' + IntToStr(Code));
      if not WizardSilent then
        MsgBox('EagleEye Agent is installed, but it could not connect with that code. Open the app and paste '
               + 'a connection code in Settings, or run setup again with a valid code.', mbError, MB_OK);
    end
    else
      Log('eagleeye.exe service enrol: connected');
  end;
end;

// 10: installed, but not connected (Intune and scripts see the install as failed).
function GetCustomSetupExitCode: Integer;
begin
  if EnrolFailed then
    Result := 10
  else
    Result := 0;
end;

// Stop the running service before its files are replaced (sc.exe exits with the Windows
// error: 0 = stop requested, 1060 = no such service, 1062 = not running), and end the app:
// asked to close, it only hides in the tray, so its EagleEyeAgent.exe stayed in use
// ("DeleteFile failed; code 5", 2026-11-07). The app holds nothing: the agent is the
// service, and the app opens again at the end and at the next sign-in.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code, I: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM EagleEyeAgent.exe /F', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if Exec(ExpandConstant('{sys}\sc.exe'), 'stop EagleEyeAgent', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0) then
    for I := 1 to 90 do
    begin
      Exec(ExpandConstant('{cmd}'), '/c sc.exe query EagleEyeAgent | find "STOPPED" > nul', '', SW_HIDE,
           ewWaitUntilTerminated, Code);
      if Code = 0 then
        Break;
      Sleep(1000);
    end;
end;

[Messages]
WelcomeLabel2=This installs [name/ver] on your computer.%n%nIt connects this computer to your organisation's EagleEye dashboard. Have the connection code from your IT administrator ready.
FinishedHeadingLabel=EagleEye Agent is installed
FinishedLabel=The agent now runs as a Windows service and starts with Windows.%n%nIf it is not set up yet: open the app, which shows what the agent collects, then paste the connection code from your IT administrator in Settings and Save (Windows asks for an administrator).%n%nThe app sits in the system tray (the blue eye icon next to the clock). Closing it does not stop the agent.
FinishedLabelNoIcons=The agent now runs as a Windows service and starts with Windows.%n%nIf it is not set up yet: open the app, which shows what the agent collects, then paste the connection code from your IT administrator in Settings and Save (Windows asks for an administrator).%n%nThe app sits in the system tray (the blue eye icon next to the clock). Closing it does not stop the agent.
