# T1036.003-4: Rename Legitimate Utilities — Masquerading - wscript.exe running as svchost.exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where adversaries copy legitimate Windows binaries under new names in locations that blend with normal process activity. This test copies `wscript.exe` (Windows Script Host) to `%APPDATA%\svchost.exe`, then executes it to run a VBScript payload. The masquerade name `svchost.exe` is one of the most common Windows process names — legitimate systems run dozens of `svchost.exe` instances — making it an attractive cover for malicious execution.

`wscript.exe` as the underlying binary is significant: it can execute VBScript and JScript files, making this technique a complete execution primitive. By copying `wscript.exe` to `svchost.exe` in the user's `AppData\Roaming` directory, the attacker creates a process that appears by name as `svchost.exe` but runs from an unusual path (legitimate `svchost.exe` always runs from `C:\Windows\System32\`). The VBScript payload used here is `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1036.003\src\T1036.003_masquerading.vbs`.

Detection of this technique is well-established: any `svchost.exe` process running from outside `C:\Windows\System32\` or `C:\Windows\SysWOW64\` is anomalous. The `OriginalFileName` field in Sysmon EID 1 will reveal `wscript.exe` even though the file is named `svchost.exe`, enabling file-header-based detection that survives renaming.

## What This Dataset Contains

This dataset contains 17,157 events: 118 PowerShell events, 16,991 Security events, 36 Sysmon events, 7 Task Scheduler events, 2 Application events, 1 System event, and 1 WMI event. The massive Security event count is driven by 16,013 EID 4663 (object access) events and 321 each of EID 4907 (audit policy change), EID 4670 (permissions changed), and EID 4664 (hard link creation attempt) — these are produced by the VBScript execution triggering Windows Installer/SxS component enumeration activity. This represents a striking difference from the defended dataset, which had only 13 Security events: with Defender disabled and the wscript payload executing, Windows SxS manifest scanning triggered extensive object access auditing.

The Security EID 4688 events tell the core story. PowerShell spawns `cmd.exe` with: `copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y & cmd.exe /c %APPDATA%\svchost.exe "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1036.003\src\T1036.003_masquerading.vbs"`. Subsequent EID 4688 events show the execution chain: `cmd.exe` spawning a child `cmd.exe`, then the masqueraded process `C:\Windows\system32\config\systemprofile\AppData\Roaming\svchost.exe` (running as SYSTEM, the `AppData` for `NT AUTHORITY\SYSTEM`) being launched with the VBScript argument.

The 4663 object access storm covers files in `C:\Windows\WinSxS\` — specifically DLL manifests for components like `cloudidsvc.dll`, `TenantRestrictionsPlugin.dll`, `SecureAssessmentHandlers.dll`, and similar Windows identity and management components. This SxS enumeration is triggered by wscript.exe's VBScript runtime resolving COM component dependencies. The 321 EID 4907 and 4670 events are paired with the hard link creation attempts (EID 4664) during this SxS activity.

Sysmon EID 1 records the `cmd.exe` launch with the copy-and-execute command, tagged `technique_id=T1059.003`. EID 13 (registry write) events show `svchost.exe` writing to registry keys. EID 7 image loads capture the standard PowerShell .NET chain plus Defender DLLs.

The System EID 7040 event shows BITS (Background Intelligent Transfer Service) changing from auto-start to demand-start — background OS activity. The WMI EID 5858 records a WMI query failure from the test framework process.

## What This Dataset Does Not Contain

Sysmon EID 1 does not capture the execution of `svchost.exe` from `AppData\Roaming\` directly — the include-mode Sysmon config does not target that path. The masqueraded process execution is visible only in Security EID 4688, not Sysmon process creation with the `OriginalFileName` field.

The VBScript payload contents are not visible in any event. No file creation (Sysmon EID 11) events capture the copy of `wscript.exe` to `svchost.exe`.

The 4663 object access events, while voluminous, do not contain meaningful attack-indicative data — they reflect Windows component resolution triggered by the VBScript runtime. They represent an interesting side-effect of full technique execution but add detection complexity rather than clarity.

## Assessment

This is an important dataset for studying two detection scenarios simultaneously: (1) the process masquerade itself (`svchost.exe` from `AppData`), and (2) the unexpected telemetry volume generated when VBScript executes fully with Defender disabled. The 16,000+ Security object access events are a notable undefended artifact — in the defended dataset the VBScript doesn't complete execution, so this volume doesn't appear. Detection engineers should be aware that successful wscript-based execution can trigger SxS component scanning that floods object access logging.

## Detection Opportunities Present in This Data

1. EID 4688 (or Sysmon EID 1) for any process named `svchost.exe` running from a path other than `C:\Windows\System32\` or `C:\Windows\SysWOW64\` is a near-certain indicator of masquerading.

2. EID 4688 command line containing `copy` with source `wscript.exe` and destination using the name `svchost.exe`, `explorer.exe`, or other high-frequency system process names in a user-writable location.

3. The parent-child chain `powershell.exe` → `cmd.exe` → `cmd.exe` → `AppData\Roaming\svchost.exe` is anomalous: legitimate `svchost.exe` instances are parented by `services.exe`, not `cmd.exe`.

4. Sysmon EID 1's `OriginalFileName` field showing `wscript.exe` (or `cmd.exe`, `powershell.exe`) when the process image name is `svchost.exe` is the most reliable detection anchor if Sysmon captures the execution.

5. A sudden burst of Security EID 4663 events from a process named `svchost.exe` running from `AppData\` is unusual — legitimate `svchost.exe` instances do not generate high volumes of SxS file access events.

6. EID 4688 for `cmd.exe /c %APPDATA%\<process_name>.exe` where `<process_name>` matches a known Windows system binary name is a strong masquerade launch indicator.
