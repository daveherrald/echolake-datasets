# T1036.003-4: Rename Legitimate Utilities — Masquerading - wscript.exe running as svchost.exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a masquerading technique where adversaries copy or rename legitimate system utilities to blend in with normal system processes. This specific test copies `wscript.exe` to `svchost.exe`, mimicking one of Windows' most common system processes. Attackers use this technique to evade signature-based detections that rely on process names and to reduce suspicion during manual analysis. The detection community focuses on identifying processes with suspicious names running from unusual paths, mismatches between process metadata and file paths, and behavioral patterns inconsistent with legitimate utilities.

## What This Dataset Contains

This dataset captures a complete masquerading scenario where `wscript.exe` is copied to `%APPDATA%\svchost.exe` and executed. The Security channel provides comprehensive process creation telemetry showing the full attack chain: PowerShell launching cmd.exe with the command `copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y & cmd.exe /c %APPDATA%\svchost.exe "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1036.003\src\T1036.003_masquerading.vbs"` (Security EID 4688).

Sysmon captures the critical file creation event showing `svchost.exe` being written to `C:\Windows\System32\config\systemprofile\AppData\Roaming\svchost.exe` (Sysmon EID 11). Most importantly, Sysmon EID 1 captures the masqueraded process creation with `Image: C:\Windows\System32\config\systemprofile\AppData\Roaming\svchost.exe` but `OriginalFileName: wscript.exe`, revealing the true identity of the binary despite the renamed file.

The dataset shows the complete process chain: PowerShell → cmd.exe → cmd.exe → svchost.exe (masqueraded wscript.exe), with all command lines preserved in Security 4688 events. Sysmon EID 7 events capture DLL loading patterns consistent with Windows Script Host execution, including `vbscript.dll` and `amsi.dll` loads.

## What This Dataset Does Not Contain

The Sysmon ProcessCreate events for the initial PowerShell and cmd.exe processes are filtered out due to the sysmon-modular include-mode configuration, which only captures processes matching suspicious patterns. However, the masqueraded `svchost.exe` process is captured because it matches the T1202 (Indirect Command Execution) rule. No registry modifications are captured as this technique only involves file system operations. Windows Defender does not block this technique, so all telemetry represents successful execution rather than blocked attempts.

## Assessment

This dataset provides excellent coverage for T1036.003 detection engineering. The combination of Security 4688 command-line logging and Sysmon file creation/process creation events creates multiple detection opportunities. The preservation of the `OriginalFileName` metadata in Sysmon EID 1 is particularly valuable, as it allows detection of the mismatch between the actual file path (`svchost.exe`) and the embedded metadata (`wscript.exe`). The complete command-line telemetry shows the copy operation and subsequent execution, enabling behavioral detection approaches.

## Detection Opportunities Present in This Data

1. **Process name/path mismatch detection** - Sysmon EID 1 shows `svchost.exe` running from user AppData directory instead of System32, with `OriginalFileName: wscript.exe` revealing the masquerade

2. **Suspicious file creation patterns** - Sysmon EID 11 captures creation of `svchost.exe` in user profile AppData\Roaming directory by cmd.exe process

3. **Command-line analysis for copy operations** - Security EID 4688 shows cmd.exe executing copy commands moving system utilities to user directories with suspicious naming

4. **Process metadata inconsistencies** - Compare process image path containing `svchost.exe` against OriginalFileName field showing `wscript.exe` in Sysmon EID 1

5. **Behavioral analysis of system process impersonation** - Detect common system process names (svchost.exe) executing from non-system directories with non-standard parent processes

6. **DLL loading pattern analysis** - Sysmon EID 7 shows script host-specific DLLs (vbscript.dll) loading into a process named svchost.exe, indicating behavioral mismatch

7. **Process ancestry validation** - Security EID 4688 reveals svchost.exe being launched by cmd.exe rather than services.exe as expected for legitimate svchost processes
