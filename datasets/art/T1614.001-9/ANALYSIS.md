# T1614.001-9: System Language Discovery — Discover System Language with WMIC

## Technique Context

T1614.001 (System Language Discovery) covers adversary attempts to identify the language and locale of a compromised host, typically to determine whether the target is in a region of interest or to avoid impacting machines in protected locales. WMIC is a classic Living-off-the-Land Binary (LOLBin) that can query OS properties including language and locale settings without installing any additional tooling.

## What This Dataset Contains

This dataset captures the full process execution chain for a WMIC-based language discovery query run via `cmd.exe` from a PowerShell test framework, executed as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**Security log (14 events)** — Event 4688 (process creation) records the full execution chain with command lines captured:
- PowerShell parent spawns `whoami.exe` (ART test framework identity check)
- PowerShell spawns `"cmd.exe" /c wmic /node:localhost os get Locale,OSLanguage,MUILanguages /format:table`
- `cmd.exe` spawns `wmic /node:localhost os get Locale,OSLanguage,MUILanguages /format:table`
- Corresponding 4689 process termination events for all three processes
- Two 4703 (Token Right Adjusted) events: one for WMIC.exe enabling a broad set of privileges (SeAssignPrimaryTokenPrivilege, SeSecurityPrivilege, SeBackupPrivilege, and others), one for the PowerShell host process

**Sysmon (31 events)** — Covers DLL image loads (EID 7) for the PowerShell process startup, named pipe creation (EID 17) for the PSHost pipe, a file creation (EID 11) for the PowerShell startup profile, and process create (EID 1) and process access (EID 10) events:
- Sysmon EID 1 captures `cmd.exe` with `RuleName: technique_id=T1059.003` and the full WMIC command line
- Sysmon EID 1 for WMIC.exe itself tagged `technique_id=T1047,technique_name=Windows Management Instrumentation`
- EID 10 (Process accessed) fires on the PowerShell process with rule `technique_id=T1055.001`

**PowerShell log (34 events)** — Predominantly test framework boilerplate: repeated EID 4104 script blocks for PowerShell error-handling internal stubs (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }`, `$_.OriginInfo`, `$_.ErrorCategory_Message`), and two EID 4103 module logging entries for `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`. No 4104 block capturing the actual WMIC invocation is present because the test command runs through `cmd.exe` rather than native PowerShell cmdlets.

## What This Dataset Does Not Contain (and Why)

- **Sysmon ProcessCreate for PowerShell** — The Sysmon config uses include-mode filtering for ProcessCreate. PowerShell itself is not on the LOLBin include list, so its process creation does not generate an EID 1; it appears only in the Security log via EID 4688.
- **WMIC output** — The query result (locale and language values) is not captured by any Windows event channel in this dataset; only the invocation is visible.
- **Network or WMI provider events** — The query targets localhost and no WMI provider or network events are generated for this local OS property query.
- **WMI activity log events** — The Microsoft-Windows-WMI-Activity/Operational channel was not included in the collection scope.

## Assessment

The test completed successfully. The full command line `wmic /node:localhost os get Locale,OSLanguage,MUILanguages /format:table` is captured in both Security EID 4688 and Sysmon EID 1. The 4703 token adjustment event for WMIC.exe is noteworthy: it shows WMIC enabling a broad set of privileges (including SeSecurityPrivilege, SeBackupPrivilege, SeRestorePrivilege) even for a simple OS property query — this is standard WMIC behavior and not indicative of privilege escalation. The dataset reflects realistic telemetry for this lightweight discovery technique on a hardened, Defender-protected host.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `wmic.exe` spawned from `cmd.exe`, which is itself spawned from `powershell.exe`, with command line containing `os get Locale,OSLanguage,MUILanguages` — this parent/child chain and WMI query topic are strong indicators.
- **Sysmon EID 1**: `wmic.exe` with `RuleName: technique_id=T1047` fires automatically from the sysmon-modular config, providing immediate labeling.
- **Security EID 4703**: Token privilege adjustment for `WMIC.exe` enabling SeSecurityPrivilege and SeBackupPrivilege can be correlated with the 4688 event to confirm process context.
- **Command line pattern**: The string `os get` combined with `Locale` or `OSLanguage` or `MUILanguages` in any process command line is a low-false-positive indicator of language discovery via WMIC.
