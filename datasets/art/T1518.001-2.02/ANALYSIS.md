# T1518.001-2: Security Software Discovery — PowerShell Process Enumeration

## Technique Context

T1518.001 (Security Software Discovery) covers adversary enumeration of defensive tooling installed on a compromised host. Understanding what endpoint security products are running is a prerequisite for evasion: an adversary who knows that Carbon Black, Cylance, or Sysmon is running will adjust their tooling, timing, and techniques accordingly. This test uses a PowerShell `Get-Process` pipeline filtered on security-product-associated description and name strings — a common, low-overhead approach that requires no elevated privileges and no external tools.

In the defended variant (586 Sysmon, 12 Security, 51 PowerShell), the script ran but Defender's behavioral monitoring may have generated additional EID 10 (ProcessAccess) events — the defended run recorded 586 Sysmon events driven primarily by EID 10 spikes. The undefended run (514 Sysmon, 127 PowerShell, 4 Security) shows the technique's own telemetry without Defender-induced artifacts, though the EID 10 count is still substantial.

## What This Dataset Contains

The dataset spans approximately 8 seconds (2026-03-17 17:05:58–17:06:06 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 645 events across three channels: 514 Sysmon, 127 PowerShell, and 4 Security.

**Security (4 events, EID 4688):** Two process creations are recorded. The first is `whoami.exe` (test framework pre-flight, creator: `powershell.exe`). The second is the technique process — a child `powershell.exe` with the full discovery script in the command line:

```
"powershell.exe" & {get-process | ?{$_.Description -like "*virus*"}
get-process | ?{$_.Description -like "*carbonblack*"}
get-process | ?{$_.Description -like "*defender*"}
get-process | ?{$_.Description -like "*cylance*"}
get-process | ?{$_.Description -like "*mc*"}
get-process | ?{$_.ProcessName -like "*mc*"}
get-process | Where-Object { $_.ProcessName -eq "Sysmon" }}
```

The full multi-line discovery script is preserved verbatim in the Security 4688 command line field, including every product name filter. This single event contains the complete indicator.

**Sysmon (514 events, EIDs 1, 7, 10, 11, 17):** The dominant contribution is EID 10 (ProcessAccess) with 479 events. These fire as the executing `powershell.exe` opens handles to each running process in order to inspect its `Description` property. Each `Get-Process | Where-Object` pipeline invocation causes PowerShell to open a handle to every process on the system, and Sysmon's `T1055.001` rule fires on each. With 7 filter queries in the script, each iterating through all running processes, the result is several hundred EID 10 events. The GrantedAccess mask `0x1FFFFF` (PROCESS_ALL_ACCESS) is recorded for each.

Sysmon EID 1 captures both `whoami.exe` (tagged `T1033`) and the discovery `powershell.exe` (tagged `T1059.001`). EID 7 records 25 DLL load events into the PowerShell processes. EID 17 records three named pipe creates. EID 11 records three file creation events.

**PowerShell (127 events, EIDs 4103, 4104):** The undefended run generates 127 PowerShell events versus 51 in the defended run. This is the most substantial increase across channels and reflects successful script execution: the discovery commands ran to completion, generating script block and module logging entries for each pipeline invocation. EID 4103 records 10 module logging events (vs. 2 in the defended run) including `Get-Process` cmdlet invocations with their `FilterScript` parameter values. EID 4104 records 117 script block entries.

The 20 sampled script blocks include the ART test framework boilerplate (`Set-ExecutionPolicy Bypass -Scope Process -Force`, `$ErrorActionPreference = 'Continue'`). The complete discovery script block — including all seven `Get-Process` filters — is captured in the Security 4688 event and the Sysmon EID 1 command line; the PowerShell 4104 samples in this dataset were populated by the formatter stubs and test framework overhead rather than the technique's own inline block (which was passed as a `& {…}` argument rather than a file-based script, causing it to be recorded in the command line rather than a distinct 4104 entry in the samples).

## What This Dataset Does Not Contain

- **No process names returned by the queries.** The `Get-Process` output — the actual list of processes evaluated against each filter — is captured in EID 4103 module logging as `FilterScript` parameter values (confirming the filter was applied) but the matching results are not in the event data.
- **No Sysmon EID 13 (RegistrySet) or EID 12 (RegistryCreate).** This technique does not touch the registry and none are expected.
- **No network events.** This is a purely local enumeration technique with no external connectivity.
- **No EID 4648 (explicit credential use) or EID 4624 (logon).** The technique runs entirely within the existing SYSTEM logon session.

## Assessment

The most striking feature of this dataset is the 479 Sysmon EID 10 (ProcessAccess) events generated by `Get-Process` enumeration. Every running process on the system is opened once per filter query, with each open generating an EID 10 because Sysmon's include-mode configuration matches `PROCESS_ALL_ACCESS` handles from PowerShell. With 7 queries and dozens of running processes, the resulting volume is high. This same pattern occurs in the defended variant (which recorded 586 Sysmon events total, with EID 10 as the dominant contributor there too), confirming the spike is intrinsic to the technique rather than a Defender artifact.

The undefended dataset also shows a substantial increase in PowerShell events: 127 vs. 51. In the defended run, the script ran but Defender's behavioral engine may have curtailed some logging or the 10 EID 4103 module logging records were not generated. Here, the full pipeline invocation detail is present.

The key finding for defenders is that the complete discovery script — all seven product filters including the explicit `Sysmon` ProcessName check — is captured in Security EID 4688 as a single, intact command line. This makes the Security channel the highest-value source for this particular technique, even in the face of the Sysmon EID 10 volume.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The complete seven-filter discovery script is present verbatim, including AV product names (`carbonblack`, `cylance`, `defender`) and the explicit `Sysmon` process name check. The inline `& {…}` command form means the full script travels in the process command line field.
- **Sysmon EID 1 command line:** Same discovery script captured with process hash and parent chain. The `T1059.001` RuleName confirms the sysmon-modular rule matched.
- **Sysmon EID 10 (ProcessAccess) volume spike:** 479 EID 10 events in under 10 seconds, all sourced from a single `powershell.exe` process with `GrantedAccess: 0x1FFFFF`, is anomalous. The combination of high-volume EID 10 from a PowerShell process with no corresponding privileged operation is characteristic of bulk process enumeration.
- **PowerShell EID 4103 (module logging):** The 10 module logging records in the undefended run (vs. 2 in the defended) provide per-cmdlet execution detail for the `Get-Process | Where-Object` pipelines, including the `FilterScript` values containing AV product name strings.
