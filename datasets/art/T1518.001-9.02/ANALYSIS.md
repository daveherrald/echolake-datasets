# T1518.001-9: Security Software Discovery — Windows Defender Enumeration

## Technique Context

T1518.001 (Security Software Discovery) covers adversary attempts to enumerate what security products are installed and how they are configured. This test targets Windows Defender specifically, using three built-in PowerShell cmdlets: `Get-Service WinDefend` (service state), `Get-MpComputerStatus` (current protection status and configuration), and `Get-MpThreat` (active threat detections). Together, these cmdlets provide a comprehensive picture of Defender's operational status — whether real-time protection is enabled, what signatures are loaded, and whether any threats are currently flagged.

In a real intrusion, this reconnaissance step informs whether it is necessary to disable Defender before proceeding, and whether any prior activity has already been detected. The use of built-in `Get-MpComputerStatus` and `Get-MpThreat` is particularly valuable to adversaries because these cmdlets query Defender's own WMI provider, returning structured data without spawning any external processes.

In the defended variant (46 Sysmon, 10 Security, 40 PowerShell), the test ran successfully — these cmdlets do not trigger Defender blocks. The undefended dataset (143 events total) is structurally comparable.

## What This Dataset Contains

The dataset spans approximately 8 seconds (2026-03-17 17:06:30–17:06:38 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 143 events across three channels: 102 PowerShell, 37 Sysmon, and 4 Security.

**Security (4 events, EID 4688):** Four process creation events. The first is `whoami.exe` (test framework pre-flight). The second is the defining event: a child `powershell.exe` spawned with the full enumeration command line:

```
"powershell.exe" & {Get-Service WinDefend
Get-MpComputerStatus
Get-MpThreat}
```

The parent chain shows SYSTEM-context `powershell.exe` at PID `0x4700` spawning the technique process. The remaining two events are the post-execution `whoami.exe` check and the cleanup invocation.

**Sysmon (37 events, EIDs 1, 7, 10, 11, 17):** Sysmon EID 1 captures both `whoami.exe` (tagged `T1033`) and the Defender enumeration `powershell.exe`. The EID 1 for the discovery process is tagged `RuleName: technique_id=T1083,technique_name=File and Directory Discovery` — a classification artifact from the sysmon-modular include-mode ruleset, which matched this PowerShell invocation pattern against its file/directory discovery rule rather than a security software discovery rule. The full command line is preserved regardless of the rule tag.

Sysmon EID 7 records 25 DLL load events into the PowerShell processes. Unlike the defended variant which included `MpOAV.dll` and `MpClient.dll` loading from Defender's platform directory (tagged `T1574.002`), this undefended dataset's EID 7 entries reflect only standard PowerShell runtime and `.NET` dependencies — the Defender DLL loads are absent because Defender is disabled. Sysmon EID 10 fires four times (ProcessAccess, `T1055.001`). EID 17 records three named pipe creates (`\PSHost.*`). EID 11 records one file creation in the SYSTEM profile temp path.

**PowerShell (102 events, EIDs 4103, 4104):** The PowerShell channel generates 102 events versus 40 in the defended run — the higher count in the undefended run is consistent with the longer per-test execution observed across the undefended session. EID 4103 records 1 module logging event (test framework `Set-ExecutionPolicy`). EID 4104 records 101 script block entries.

The technique-specific cmdlets — `Get-Service WinDefend`, `Get-MpComputerStatus`, `Get-MpThreat` — are invoked in an inline `& {…}` block whose full content is captured in the Security EID 4688 and Sysmon EID 1 command lines. The 101 EID 4104 entries in the sample set are predominantly internal PowerShell formatter stubs generated during the cmdlet execution.

## What This Dataset Does Not Contain

- **No output from the cmdlets.** Whether Defender appeared as running, disabled, or what `Get-MpThreat` returned is not visible in event logs. The fact that Defender is disabled via GPO means `Get-Service WinDefend` would return a stopped or not-running state, and `Get-MpComputerStatus` / `Get-MpThreat` would return limited or error output — but none of this is captured.
- **No Defender DLL loads (Sysmon EID 7).** In the defended variant, `MpOAV.dll` and `MpClient.dll` loaded into the enumeration PowerShell process, tagged `T1574.002`. Those are absent here. This absence is itself a useful point of comparison: an analyst working a defended environment would see these DLL loads and know Defender was active at the time of enumeration.
- **No `wmiprvse.exe` or WMI provider process.** `Get-MpComputerStatus` and `Get-MpThreat` use the Defender WMI provider, but no `wmiprvse.exe` EID 1 is recorded in this dataset (unlike T1518.001-11 where WMI spawned a separate process). The cmdlets appear to have queried Defender's provider through an in-process COM call.

## Assessment

This dataset pairs naturally with T1518.001-11 (querying Defender exclusions via WMIC). Together, the two tests cover the most common Defender enumeration patterns: service state and protection status via PowerShell cmdlets (this test), and exclusion configuration via legacy WMIC (T1518.001-11).

The defended and undefended variants for this test are functionally equivalent from an indicator standpoint — neither triggers a Defender block, and the core command line evidence is present in both. The key difference is in Sysmon EID 7: the defended run includes Defender DLL loads into the enumeration process, confirming Defender was active and monitoring; the undefended run lacks those loads, confirming Defender was absent.

On ACME-WS06 with Defender disabled via GPO, the `Get-MpComputerStatus` and `Get-MpThreat` cmdlets still execute (they are part of the `ConfigDefender` PowerShell module) but return data reflecting the disabled state. This means the technique generates identical telemetry regardless of whether Defender is actually active — a defender cannot determine from these events alone whether Defender was running at the time of enumeration.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The three-cmdlet block `Get-Service WinDefend`, `Get-MpComputerStatus`, `Get-MpThreat` is preserved verbatim in the child `powershell.exe` command line. The combination of these cmdlets in a single block is highly specific to Defender enumeration.
- **Sysmon EID 1 command line:** Same multi-cmdlet block captured with full process hash and parent chain. The `T1083` tag is a false positive from the sysmon-modular ruleset, but the command line content is unambiguous.
- **Parent-child PowerShell spawn:** The pattern of a SYSTEM-context `powershell.exe` spawning a child `powershell.exe` with a security enumeration cmdlet block is consistent across multiple T1518.001 tests in this dataset batch and represents a useful correlation signature.
- **Sysmon EID 7 DLL load absence (undefended indicator):** In defended environments, Defender DLL loads into processes that invoke `Get-MpComputerStatus` provide an implicit confirmation that Defender was monitoring the call. Their absence in this dataset confirms the Defender-disabled context.
