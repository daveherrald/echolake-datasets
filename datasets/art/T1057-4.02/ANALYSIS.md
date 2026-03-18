# T1057-4: Process Discovery — Process Discovery via Get-WmiObject Win32_Process

## Technique Context

T1057 Process Discovery covers the range of methods adversaries use to enumerate running processes. This specific test uses PowerShell's `Get-WmiObject -class Win32_Process` — a WMI-based approach that returns significantly richer data than `tasklist.exe`. The `Win32_Process` class exposes process names, PIDs, parent PIDs, command lines, creation dates, executable paths, session IDs, and owner information in a structured format queryable with standard PowerShell object manipulation. This makes it a preferred method when attackers need to process the output programmatically rather than parse plain text.

WMI-based process enumeration is harder to detect by simplistic string matching than `tasklist` because it does not spawn a distinct discovery binary — the entire query happens within the PowerShell process itself via the WMI COM infrastructure. The execution chain is just `powershell.exe` querying `winmgmt`, with no `tasklist.exe` or `wmic.exe` child process. Detection requires either PowerShell script block logging (which captures the `Get-WmiObject` call) or WMI activity monitoring, both of which are present in this dataset.

Because WMI is a legitimate administrative interface used constantly by Windows components, context is everything: the same `Win32_Process` query run by SCCM, Defender, or a monitoring agent is routine, while the same query run by a PowerShell process spawned under `NT AUTHORITY\SYSTEM` from an ART-style test framework is anomalous.

## What This Dataset Contains

The dataset spans five seconds (2026-03-14T23:17:15Z to 23:17:20Z) and records 134 events across three channels: Sysmon (34), PowerShell (96), and Security (4). No Application channel events are present.

**Security EID 4688** records four process creation events:
- `"C:\Windows\system32\whoami.exe"` — pre-test identity check
- `"powershell.exe" & {get-wmiObject -class Win32_Process}` — the technique invocation
- `"C:\Windows\system32\whoami.exe"` — post-test identity check
- `"powershell.exe" & {}` — the cleanup step

The second event is the key artifact: the full command line `& {get-wmiObject -class Win32_Process}` is captured verbatim in `NewProcessCommandLine` / `CommandLine`. This command line is the single most valuable detection artifact in the dataset — it leaves a clear, specific footprint in security audit logs.

**Sysmon EID 1** captures the same process creation events with additional metadata. No child process spawned by `Get-WmiObject` appears — the WMI query runs entirely within `powershell.exe`, confirming that this technique leaves no discovery-specific child process artifact. This is the fundamental difference from tests T1057-2 and T1057-6, which both spawn `tasklist.exe` as a child process.

**Sysmon EID 10 (ProcessAccess)** shows four cross-process access events. All use `GrantedAccess: 0x1FFFFF` with CLR call traces. Targets include `whoami.exe` and a PowerShell process — the same framework-generated pattern seen in other ART tests. Notably, `winmgmt.exe` or any WMI host does not appear as a target of process access, confirming that `Get-WmiObject` uses COM/DCOM over local RPC rather than direct process injection.

**Sysmon EID 7 (ImageLoad)** contributes 22 events, dominated by .NET runtime DLL loads (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`) followed by `MpOAV.dll`, `MpClient.dll`, and `urlmon.dll`. This is consistent with a PowerShell process that loads the full .NET CLR runtime for WMI object access.

**Sysmon EID 17 (PipeCreate)** records the PowerShell host pipe: `\PSHost.134180038332172088.3156.DefaultAppDomain.powershell`.

**PowerShell EID 4104** contributes 95 script block events. The critical block `get-wmiObject -class Win32_Process` is captured by script block logging, providing a second source confirming the technique payload beyond the command line. **EID 4103** (module invocation logging) contributes 1 event, recording the specific cmdlet and parameters called.

Compared to the defended version (29 sysmon, 16 security, 34 PowerShell), the undefended dataset shows more Sysmon events (34 vs. 29) and fewer Security events (4 vs. 16). The higher Sysmon count likely reflects additional DLL load events captured in the undefended run, while the defended Security count likely includes Defender-generated process creation events.

## What This Dataset Does Not Contain

No WMI-specific events (such as Windows WMI Activity Operational log events) are present — this dataset covers Sysmon, Security, and PowerShell channels only. WMI activity logging would add visibility into the actual query parameters and results.

No network connection events appear. WMI process enumeration over the local interface does not generate remote connections; if this technique were used remotely (e.g., `Get-WmiObject -ComputerName <target>`), Sysmon EID 3 and Security EID 4624/4648 events would appear.

The output of the `Win32_Process` query — the actual list of running processes — is not captured in any event. Detection tells you the query ran, not what it returned.

## Assessment

This dataset provides clean, specific evidence of WMI-based process discovery through the `Get-WmiObject Win32_Process` pattern. The technique leaves an unusually clear footprint in Security EID 4688 because the full PowerShell command is captured as the child process's command line when the test framework invokes it as `powershell.exe & {get-wmiObject -class Win32_Process}`. Script block logging (EID 4104) and module logging (EID 4103) provide corroborating evidence in the PowerShell channel.

The dataset is particularly useful for demonstrating why WMI-based discovery is behaviorally different from binary-based discovery at the process-creation level, and why coverage of WMI enumeration requires PowerShell logging rather than just process execution monitoring.

## Detection Opportunities Present in This Data

1. **`Get-WmiObject Win32_Process` in Security EID 4688 command line**: The command `get-wmiObject -class Win32_Process` appears verbatim in the `NewProcessCommandLine` field of Security EID 4688. Case-insensitive matching on this pattern in process creation events is a high-fidelity indicator.

2. **`Get-WmiObject Win32_Process` in PowerShell EID 4104**: Script block logging captures the same payload in `ScriptBlockText`. This provides a second, independent detection point that survives scenarios where command-line logging is incomplete.

3. **PowerShell EID 4103 (module logging) combined with Win32_Process**: EID 4103 records the cmdlet invocation with parameters. Alerting on `Get-WmiObject` calls that query `Win32_Process` via module logging, filtered to unusual execution contexts (SYSTEM, non-interactive, unusual parent), provides good precision.

4. **No child process from PowerShell despite discovery-context execution**: If you detect reconnaissance behavior (e.g., `whoami.exe` execution) followed by a PowerShell invocation but no `tasklist.exe` or `wmic.exe` child process, WMI-based discovery is a likely explanation. Absence of a discovery binary child can itself be a behavioral signal when combined with other context.

5. **Parent PowerShell spawning child PowerShell with WMI command**: The test framework pattern shows `powershell.exe (parent) → powershell.exe (child) & {get-wmiObject ...}`. A non-interactive PowerShell spawning a child PowerShell with explicit WMI cmdlets is an anomalous execution pattern.

6. **NT AUTHORITY\SYSTEM running WMI process queries in a scripted context**: The `User: NT AUTHORITY\SYSTEM` field on the PowerShell process executing `Win32_Process` queries, combined with the parent-child process chain, distinguishes this from legitimate administrative WMI usage which typically runs under a named administrator account interactively.
