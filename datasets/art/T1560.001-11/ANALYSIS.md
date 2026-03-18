# T1560.001-11: Archive via Utility — Compress a File for Exfiltration using Makecab

## Technique Context

T1560.001 (Archive via Utility) covers adversaries compressing collected data prior to exfiltration, using system-native or third-party archiving tools to reduce transfer size and potentially evade content-based detection. This test uses `makecab.exe`, the Windows Cabinet (CAB) file format utility that ships with every version of Windows. Makecab is a living-off-the-land binary (LOLBin): it is signed by Microsoft, present on all Windows systems by default, and produces output files with arbitrary extensions — including `.zip` — even though the output is actually in CAB format. Adversaries use makecab to compress sensitive files (such as SAM hive dumps, credential files, or document collections) before staging them for exfiltration. The technique has been observed in post-exploitation phases of credential-harvesting campaigns targeting Exchange servers.

## What This Dataset Contains

This dataset spans 4 seconds (01:20:34–01:20:38 UTC) across 16 Sysmon events and 12 Security events.

**Sysmon EID 1** and **Security EID 4688** capture the full process chain. The ART framework's parent PowerShell (PID 2772) first spawns `whoami.exe` as a preflight check, then spawns `cmd.exe` (PID 1236) with the command `"cmd.exe" /c makecab.exe C:\Temp\sam.hiv C:\Temp\art.zip`. The `cmd.exe` process in turn spawns `makecab.exe` (PID 5444) with `makecab.exe C:\Temp\sam.hiv C:\Temp\art.zip`. Both the `cmd.exe` wrapper and the `makecab.exe` execution are visible with full command-line arguments in both Sysmon EID 1 (tagged `technique_id=T1059.003`) and Security EID 4688.

The input file `C:\Temp\sam.hiv` represents a SAM registry hive export — a common target for credential extraction operations. The output `C:\Temp\art.zip` uses a `.zip` extension despite containing CAB-format data, a common obfuscation approach used to bypass file-type filtering.

**Sysmon EID 7** (Image loaded) captures 9 DLL load events for the two PowerShell processes, including .NET runtime components and Windows Defender integration modules — normal overhead from PowerShell initialization.

**Sysmon EID 10** (Process accessed) shows two process access events from the parent PowerShell accessing child processes, tagged `technique_id=T1055.001` (DLL injection) by the sysmon-modular rules due to the access mask pattern.

**Sysmon EID 17** (Pipe created) captures one `\PSHost.*` named pipe from the executing PowerShell process.

**Security EID 4689** (Process termination) records the exit of all spawned processes. **Security EID 4703** (Token right adjusted) captures one privilege adjustment in the parent PowerShell process.

## What This Dataset Does Not Contain

No Sysmon EID 11 (File created) event confirms the creation of the output archive `C:\Temp\art.zip`. The Sysmon FileCreate rule did not fire on the makecab output — either because the `C:\Temp\` path is not covered by the FileCreate include filter, or because makecab's file creation mechanism was not captured. The absence of an EID 11 means you cannot confirm successful compression from Sysmon alone; the process execution evidence is the primary indicator.

There are no PowerShell script block events (EID 4103/4104) in this dataset. The technique executes through `cmd.exe` and `makecab.exe` rather than inline PowerShell, so no script block logging is expected.

There are no network events (Sysmon EID 3) showing data being transferred after archiving. This dataset captures only the compression phase, not any subsequent exfiltration.

No Security file access auditing events (4656, 4663) are present for the input file `C:\Temp\sam.hiv`. Object access auditing is not enabled in this environment.

## Assessment

This is a clean, minimal dataset that directly captures the use of `makecab.exe` for data compression in a credential-exfiltration context. The process chain is unambiguous: PowerShell → cmd.exe → makecab.exe with the SAM hive as input. The small event count (28 total events) means there is very little noise, and the signal — makecab.exe executing under SYSTEM with a `.hiv` file as input and a deceptively named `.zip` as output — is highly specific. This dataset is well-suited for building and validating detections targeting makecab LOLBin abuse. The absence of file creation confirmation in Sysmon is worth noting for analysts expecting EID 11 as corroboration; in this case the process creation record is sufficient to identify the activity.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `makecab.exe` spawned from `cmd.exe` with a `.hiv` file as input; SAM, NTDS, or registry hive files as makecab input arguments are a high-confidence indicator of credential staging for exfiltration.

- **Sysmon EID 1 / Security EID 4688**: `makecab.exe` producing output with a `.zip`, `.pdf`, or other non-CAB extension; the mismatch between the actual CAB format and the output filename extension is a characteristic evasion pattern worth flagging on its own.

- **Security EID 4688**: `cmd.exe` spawned from PowerShell with a command line containing `makecab.exe` and a path under `C:\Temp\`; PowerShell invoking makecab through a cmd wrapper is unusual and suggests programmatic execution rather than interactive use.

- **Process ancestry**: `makecab.exe` with a parent of `cmd.exe` and a grandparent of `powershell.exe` running as SYSTEM; the full three-process chain (PS → cmd → makecab) under SYSTEM context has no legitimate equivalent in normal Windows operations.

- **Sysmon EID 10**: PowerShell accessing a child process with an access mask that sysmon-modular tags as T1055.001; while this fires on normal PS child process interactions, correlating it with a subsequent makecab execution tightens the behavioral signature.
