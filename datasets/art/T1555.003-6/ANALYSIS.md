# T1555.003-6: Credentials from Web Browsers — Simulating access to Windows Firefox Login Data

## Technique Context

T1555.003 (Credentials from Web Browsers) covers adversary attempts to extract saved credentials from browser profile stores. Firefox stores credentials in `logins.json` and `key4.db` within the user profile under `%APPDATA%\Mozilla\Firefox\Profiles\`. Attackers commonly exfiltrate these files to decrypt offline. This test simulates that behavior by copying the Firefox Profiles directory to a staging location.

## What This Dataset Contains

The dataset spans six seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The core activity was a single PowerShell `Copy-Item` invocation copying the Firefox profile directory:

```
Copy-Item "$env:APPDATA\Mozilla\Firefox\Profiles\" -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads" -Force -Recurse
```

This appears in EID 4104 (script block logging) twice — once wrapped in `& { ... }` and once as the bare block. EID 4103 (module logging) records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — the ART test framework boilerplate that runs before every test.

Sysmon events include:
- **EID 1** (Process Create): `whoami.exe` (tagged T1033) and a second `powershell.exe` instance (tagged T1059.001), both spawned as children of the test framework process
- **EID 7** (ImageLoad): Multiple DLLs loaded into PowerShell — `mscoree.dll`, .NET Framework v4 assemblies — tagged T1055/T1574.002 by sysmon-modular rules
- **EID 10** (ProcessAccess): PowerShell accessing another PowerShell process (SourceProcessId → TargetProcessId), tagged T1055.001 — typical of in-process .NET hosting via the ART test framework
- **EID 11** (FileCreate): PowerShell transcript files written to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`
- **EID 17** (PipeCreate): Named pipes `\PSHost.<timestamp>.<pid>.DefaultAppDomain.powershell` from each PowerShell instance

Security events include EID 4688/4689 (process create/exit for powershell.exe and conhost.exe) and EID 4703 (token right adjusted) for the SYSTEM account.

## What This Dataset Does Not Contain (and Why)

**No file access events for the Firefox profile itself.** Object access auditing is disabled (`object_access: none`), so there are no EID 4663 records showing reads of `logins.json` or `key4.db`. The Copy-Item succeeded silently from a Windows audit perspective.

**No LSASS access.** This technique does not require LSASS interaction; browser credentials are stored on disk and readable by the token's user context.

**No Sysmon EID 1 for the Copy-Item itself.** The Sysmon ProcessCreate configuration uses include-mode filtering and does not have a rule matching `powershell.exe` as a generic process — the second `powershell.exe` was captured because it matched the T1059.001 rule. The actual file copy was performed within PowerShell's in-process cmdlet, not a child process.

**No network events.** The test only copies locally; exfiltration is not simulated.

## Assessment

This is a blocked-by-intent but telemetry-generating test. Sysmon's include-mode ProcessCreate filtering means that not every powershell.exe invocation produces an EID 1 — but the test framework's whoami.exe (T1033 match) and the spawned powershell.exe (T1059.001 match) were both captured. The most forensically valuable artifact is the EID 4104 script block showing the exact Copy-Item target path. The absence of file access auditing means a defender relying solely on Windows Security logs would see process creation but not the credential file access.

## Detection Opportunities Present in This Data

- **EID 4104**: Script block logs the exact command — `Copy-Item` targeting `$env:APPDATA\Mozilla\Firefox\Profiles\` is a high-confidence indicator when combined with the destination path under `AtomicRedTeam\ExternalPayloads` or any staging directory.
- **EID 1 (Sysmon)**: `whoami.exe` spawned from PowerShell under SYSTEM context is anomalous on a workstation and consistent with attacker reconnaissance prior to credential staging.
- **EID 4688**: Security process creation with command-line auditing confirms `powershell.exe` execution under `NT AUTHORITY\SYSTEM` (Logon ID `0x3E7`).
- **Correlation**: EID 4104 script block + EID 11 transcript write to the SYSTEM profile path establishes the execution context and timing needed for triage.
