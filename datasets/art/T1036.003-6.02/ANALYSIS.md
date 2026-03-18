# T1036.003-6: Rename Legitimate Utilities — Masquerading - non-windows exe running as windows exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) covers adversaries renaming files to masquerade as legitimate utilities. This test takes a different approach from the other T1036.003 variants: instead of renaming a built-in Windows binary, it copies a custom non-Windows executable (`C:\AtomicRedTeam\atomics\T1036.003\bin\T1036.003.exe`) to `$env:TEMP\svchost.exe` and executes it. This represents the more realistic attacker scenario — placing actual malicious code under the name of a trusted Windows process.

The `T1036.003.exe` binary included with Atomic Red Team is a benign test payload designed to simulate what an attacker's tool would look like when deployed via this technique. By landing it in `$env:TEMP` as `svchost.exe`, the test validates detection coverage for payloads that masquerade as one of Windows' most ubiquitous process names. The attack uses PowerShell's `Start-Process` to launch the renamed binary and `Stop-Process` to terminate it.

What makes this variant more operationally relevant than renaming `cmd.exe` to `lsass.exe` (T1036.003-1) is that the underlying binary is not a standard Windows component — it will have different PE metadata, different `OriginalFileName` header values, a different (or absent) digital signature, and different image hash values. Detection systems that validate process signatures or check `OriginalFileName` against the process image name will fire on this, while those relying solely on path-based detection will behave similarly to the other variants.

## What This Dataset Contains

This dataset contains 140 events: 100 PowerShell events, 7 Security events, 32 Sysmon events, 1 Application event, and 7 Task Scheduler events.

The Security channel (EID 4688) captures the full execution chain. The primary attack command is a PowerShell invocation: `copy "C:\AtomicRedTeam\atomics\T1036.003\bin\T1036.003.exe" ($env:TEMP + "\svchost.exe")` followed by `Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")`. The masqueraded binary executing appears as `EID 4688: CommandLine: C:\Windows\TEMP\svchost.exe, NewProcessName: C:\Windows\Temp\svchost.exe, ParentProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. The cleanup is captured: `Remove-Item ($env:TEMP + "\svchost.exe") -Force -ErrorAction Ignore`.

A background EID 4688 records `sppsvc.exe` (Software Protection Platform) launching from `services.exe` and `taskhostw.exe` from `svchost.exe` — these are OS activities coinciding with the test window, not technique-related. EID 4702 records a task scheduler update for `\Microsoft\Windows\Flighting\OneSettings\RefreshCache`.

Sysmon EID 1 captures the PowerShell invocation with the full copy-and-launch command, tagged `technique_id=T1059.001`. EID 11 (file create) records `powershell.exe` creating `C:\Windows\Temp\svchost.exe` — a direct file system artifact of the deployment. EID 10 shows `powershell.exe` accessing `whoami.exe` memory. EID 17 (pipe create) events bookend the PowerShell execution contexts. Notably, Sysmon EID 29 (file executable detected) appears — this is Sysmon's detection of a new executable file, which fired on the `svchost.exe` copy being created.

Compared to the defended dataset (36 Sysmon, 10 Security, 46 PowerShell), the undefended version has similar counts. The main difference is that the defended dataset would show Defender blocking or alerting on the non-Windows executable being dropped and executed; here that interference is absent and the execution completes cleanly.

## What This Dataset Does Not Contain

The `OriginalFileName` of `T1036.003.exe` is not visible in the Security EID 4688 events (that field is only in Sysmon EID 1). Since Sysmon EID 1 does not capture the masqueraded process itself (it's not in the Sysmon include rules as a LOLBin), the `OriginalFileName` discrepancy that would identify this as non-Windows code is not present in this dataset's samples.

No network connections from the masqueraded process are captured. No memory analysis of the `T1036.003.exe` payload content is available.

## Assessment

This dataset is particularly valuable because it demonstrates the file creation artifact (Sysmon EID 11 + EID 29) alongside the process execution (Security EID 4688). The combination of an executable file written to `$env:TEMP` with a Windows system process name, immediately followed by a process creation event for that same path from `powershell.exe`, is a clean detection chain. The Sysmon EID 29 (file executable detected) is worth highlighting — it specifically flags the creation of a new PE file in a writable location.

## Detection Opportunities Present in This Data

1. Sysmon EID 11 (file create) for an `.exe` file created in `$env:TEMP` with a name matching a known Windows system process (`svchost.exe`, `lsass.exe`, etc.) is a high-fidelity indicator.

2. Sysmon EID 29 (file executable detected) fires when a new PE file is created — when combined with a path in a user-writable directory and a system-process-matching filename, this warrants immediate investigation.

3. EID 4688 for a process running from `C:\Windows\Temp\svchost.exe` (or any writable directory) with parent `powershell.exe` is anomalous — legitimate `svchost.exe` is never launched from `powershell.exe`.

4. The temporal sequence of Sysmon EID 11 (file write to `$env:TEMP\svchost.exe`) immediately followed by EID 4688 (process creation for `$env:TEMP\svchost.exe`) within the same PowerShell execution context is a precise indicator of deploy-and-execute masquerade behavior.

5. Sysmon EID 1 with `OriginalFileName` not matching the process image name (e.g., `OriginalFileName: T1036.003.exe` vs. image `svchost.exe`) would be the most reliable single-event detection, if the Sysmon configuration captures the masqueraded process launch.
