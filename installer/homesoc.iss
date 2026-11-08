; Inno Setup 6 script for HomeSOC (CLAUDE.md §4, §8). Build the PyInstaller bundle first:
;     .venv\Scripts\pyinstaller installer\homesoc.spec      -> dist\HomeSOC\
; then compile this file (Inno Setup Compiler, or: ISCC.exe installer\homesoc.iss)
;     -> dist\HomeSOC-Setup.exe
;
; Installs into C:\Program Files\HomeSOC (read-only):
;   HomeSOC-Agent.exe  elevated: a scheduled task runs it as SYSTEM (highest privileges) at
;                      startup, and setup starts it right away (Npcap capture + firewall need it).
;   HomeSOC.exe        the app, normal user: Start-menu entry, all-users Startup entry, and
;                      launched after setup as the user who ran setup (not elevated).
; Writable data (config.yaml, SQLite db, data\cache, evidence, ring pcap, agent.log) lives in
; %PROGRAMDATA%\HomeSOC; the agent seeds it from the bundle (agent/config.py: seed_data_root).
;
; Uninstall stops both programs, deletes the scheduled task and removes the firewall rules in
; group HomeSOC ONLY (§9.3): no other firewall or Defender setting is ever touched.
; tests/test_installer.py parses this file and checks that.

#define AppName "HomeSOC"
; Shown to the user (wizard, Start menu, Startup, Apps & features). Internal names (folders,
; exe names, the scheduled task, the firewall group) stay HomeSOC on purpose (CLAUDE.md §6.7).
#define AppDisplayName "MoCat HomeSOC"
#define AppVersion "0.1.0"
#define AgentExe "HomeSOC-Agent.exe"
#define AppExe "HomeSOC.exe"
#define AgentTask "HomeSOC Agent"

[Setup]
AppId={{B79FCC82-AF9F-4E78-B414-33E688145F75}
AppName={#AppDisplayName}
AppVersion={#AppVersion}
AppPublisher=HomeSOC hackathon team
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppDisplayName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=HomeSOC-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; installer\mocat.ico (paths are relative to this file); regenerate with installer\make_icon.py
SetupIconFile=mocat.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppDisplayName}

[Files]
Source: "..\dist\HomeSOC\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Shortcuts of an install from before the MoCat rename (else the app would start twice at logon).
Type: files; Name: "{autoprograms}\HomeSOC.lnk"
Type: files; Name: "{commonstartup}\HomeSOC.lnk"

[Icons]
Name: "{autoprograms}\{#AppDisplayName}"; Filename: "{app}\{#AppExe}"
Name: "{commonstartup}\{#AppDisplayName}"; Filename: "{app}\{#AppExe}"

[Run]
; Agent: register the elevated startup task (no 72 h time limit, restart on failure) and start it.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$a = New-ScheduledTaskAction -Execute '{app}\{#AgentExe}'; $t = New-ScheduledTaskTrigger -AtStartup; $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); Register-ScheduledTask -TaskName '{#AgentTask}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null; Start-ScheduledTask -TaskName '{#AgentTask}'"""; Flags: runhidden waituntilterminated; StatusMsg: "Starting the HomeSOC agent..."
; App: as the user who ran setup, not elevated.
Filename: "{app}\{#AppExe}"; Description: "Open {#AppDisplayName}"; Flags: nowait postinstall runasoriginaluser skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Unregister-ScheduledTask -TaskName '{#AgentTask}' -Confirm:$false"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteAgentTask"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM {#AgentExe}"; Flags: runhidden waituntilterminated; RunOnceId: "StopAgent"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden waituntilterminated; RunOnceId: "StopApp"
; Firewall cleanup: the HomeSOC group only (§9.3).
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -Command ""Remove-NetFirewallRule -Group 'HomeSOC'"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveHomeSOCFirewallRules"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not DirExists(ExpandConstant('{sys}\Npcap')) then
    Result := MsgBox('Npcap was not found. HomeSOC needs it to see network traffic: install ' +
      'Wireshark (it includes Npcap) first.' + #13#10#13#10 + 'Continue anyway?',
      mbConfirmation, MB_YESNO) = IDYES;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { Stop a running copy so its files can be replaced (reinstall / upgrade). }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM {#AgentExe}', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
