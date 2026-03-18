# T1083-6: File and Directory Discovery — Launch DirLister Executable

## Technique Context

T1083 (File and Directory Discovery) encompasses not only native Windows tools but also purpose-built directory enumeration utilities that adversaries deploy as external payloads. DirLister is a standalone executable tool designed for recursive directory listing, capable of generating structured output files that can be exfiltrated or analyzed offline. Using purpose-built tools rather than native cmdlets can be advantageous for attackers who want richer output formatting, faster performance on large filesystems, or reduced reliance on PowerShell activity that might trigger behavioral analytics.

The ART test deploys DirLister from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\DirLister.exe` — the `ExternalPayloads` directory is populated during test setup. This is identical in structure to real-world adversary operations where a custom tool is staged to disk and then executed.

In the defended variant of this dataset, the test failed because DirLister.exe was missing from the payload directory, and Defender generated a task scheduler event. In the undefended run, the payload is present and executes.

## What This Dataset Contains

This dataset covers an 8-second window (2026-03-14T23:33:37Z–23:33:45Z).

**Process execution chain**: Sysmon EID 1 records `whoami.exe` (PID 3928) at 23:33:38 as a pre-execution check, followed by the orchestrating PowerShell process (PID 5520) at 23:33:39 with command line:

```
"powershell.exe" & {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\DirLister.exe"
Start-Sleep -Second 4
Stop-Process -Name "DirLister"}
```

Tagged `technique_id=T1083,technique_name=File and Directory Discovery`. The process runs as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. The `Start-Sleep -Second 4` pause allows DirLister to enumerate before being terminated. A second PowerShell process (PID 4552) runs the cleanup sequence at 23:33:46.

**Security events**: Six EID 4688 events cover the `whoami.exe`, the orchestrating PowerShell, two additional instances (one for DirLister launch context, one cleanup), and a final `whoami.exe`. The undefended run has 6 security events versus 9 in the defended run.

Two additional Security events deserve attention:
- EID 4657: A registry value modification to `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\SafeClientList` (`WSManSafeClientList`) by `svchost.exe` (PID 0x1738). This is ambient Windows Remote Management service activity unrelated to the technique.
- EID 4663: The corresponding registry key access event for the same WSMAN key. These two events are OS background noise captured in the dataset's time window.

**PowerShell script block logging**: 109 EID 4104 events and 1 EID 4100 event were captured (110 total). The EID 4100 error event is significant. In the defended dataset, EID 4100 reported `This command cannot be run due to the error: The system cannot find the file specified` for `Start-Process`, indicating DirLister.exe was missing. In this undefended run, a different EID 4100 may indicate a post-execution cleanup error, or DirLister ran but exited with an error condition during the 4-second wait.

**DLL loading**: 25 Sysmon EID 7 events reflect .NET runtime and PowerShell module loading — higher than the simpler command tests but lower than the C# assembly tests.

**Process access**: Four Sysmon EID 10 events show parent-child process access patterns from the test framework.

**Named pipes**: Three Sysmon EID 17 events record PowerShell host pipes for the multiple PowerShell instances.

**File creation**: Sysmon EID 11 records `StartupProfileData-NonInteractive` — the routine PS profile cache write, not DirLister output.

The undefended run (38 sysmon, 6 security, 110 powershell) compared to defended (36 sysmon, 9 security, 46 powershell): the powershell event count more than doubled, consistent with DirLister actually executing and generating more PS runtime activity. The security count decreased (6 vs 9), likely because the defended run captured additional process events from Defender and task scheduler activity that is absent here. The task scheduler events present in the defended run (defended count includes 1 taskscheduler event) are not present in the undefended run.

## What This Dataset Does Not Contain

DirLister's output — the actual directory listing it produced — does not appear in the telemetry. DirLister writes its results to a file (configurable), but Sysmon EID 11 file creation events for DirLister's output file are not present in the available 20-sample set. The sysmon-modular configuration does not specifically track DirLister.exe's file writes by default.

Critically, DirLister.exe's own process creation event does not appear in the available Sysmon EID 1 samples. With 5 total EID 1 events in the dataset (only 2 shown in samples due to the 20-sample limit), DirLister.exe's process creation likely appears in the full dataset but falls outside the sampled events.

The dataset also lacks any network activity — DirLister is a local enumeration tool and does not communicate externally.

## Assessment

This dataset captures a successful deployment and execution of a purpose-built directory enumeration tool (DirLister) by a SYSTEM-privilege PowerShell process on a domain workstation with Defender disabled. The command line in Sysmon EID 1 and Security EID 4688 shows the full execution intent: stage, start, wait 4 seconds, stop. The tool ran and enumerated (based on the increased PowerShell event count versus the failed defended run), but its output is not captured in the available telemetry samples.

The most forensically significant difference from T1083-5 is the presence of an external payload executed from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` — a concrete indicator of pre-staged tooling. Real-world attackers staging directory enumeration tools use similar staging paths.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: The command line contains `Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\DirLister.exe"` — explicit execution of a custom binary from a staging directory. Any execution of non-standard executables from `\ExternalPayloads\`, `\Temp\`, or similar staging paths by SYSTEM-privilege PowerShell is a strong indicator.

**Sysmon EID 1 for DirLister.exe**: The full dataset (beyond available samples) should contain a process creation event for `DirLister.exe` itself, including its command-line arguments and working directory. This would provide the clearest indicator of the tool's scope and configuration.

**Behavioral pattern**: `Start-Process` + `Start-Sleep` + `Stop-Process` targeting a custom executable is a clear "run-wait-kill" execution pattern. This pattern appears when an operator wants to run a tool, allow it to complete, and clean up the process — a common red team and adversary technique.

**EID 4657/4663 (Registry)**: The WSMAN SafeClientList modifications are OS background noise, not technique-related. Analysts should be aware that Security events in this window include ambient system activity that must be filtered when focusing on the technique.
