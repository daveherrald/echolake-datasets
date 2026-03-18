# T1112-76: Modify Registry — Requires the BitLocker PIN for Pre-boot authentication

## Technique Context

T1112 (Modify Registry) represents adversaries' use of registry modifications to establish persistence, escalate privileges, disable security controls, or evade defenses. The registry is a critical Windows component that stores configuration data for the operating system and applications, making it an attractive target for attackers seeking to modify system behavior.

This specific test focuses on BitLocker configuration modification — specifically setting the `UseAdvancedStartup` registry value to enable advanced startup options, including PIN requirements for pre-boot authentication. While this particular modification might appear administrative rather than malicious, registry modifications targeting BitLocker settings are commonly used by ransomware operators to disable encryption or manipulate boot processes. Detection engineers focus on monitoring registry writes to critical system areas, especially those affecting security controls, boot processes, and encryption settings.

## What This Dataset Contains

The dataset captures a PowerShell-based registry modification that executes successfully through a cmd.exe wrapper. The key events show:

**Process Chain**: Three PowerShell processes (PIDs 16580, 31384, 32680) spawn sequentially, with the second PowerShell instance (31384) executing the actual registry modification command.

**Registry Modification Command**: Security EID 4688 shows cmd.exe executing: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseAdvancedStartup /t REG_DWORD /d 1 /f`

**Complete Process Tree**: PowerShell → cmd.exe (PID 32548) → reg.exe (PID 21928), with Security events 4688 capturing each process creation with full command lines.

**Sysmon Coverage**: EID 1 events capture whoami.exe, cmd.exe, and reg.exe executions with full command-line arguments. EID 10 shows PowerShell accessing child processes with full access rights (0x1FFFFF). EID 7 events document .NET runtime loading within PowerShell processes.

**PowerShell Telemetry**: EID 4103/4104 events show only test framework boilerplate (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` and standard error handling scriptblocks) — the actual registry modification command does not appear in PowerShell logging.

## What This Dataset Does Not Contain

The dataset lacks the most critical piece for T1112 detection: **actual registry modification events**. There are no Sysmon EID 13 (Registry value set) or EID 12 (Registry object added or deleted) events, likely because the sysmon-modular configuration doesn't monitor the `HKLM\SOFTWARE\Policies\Microsoft\FVE` registry path.

No object access auditing events (Security EID 4656/4658) show the registry write operation, indicating that object-level auditing for registry operations isn't configured for this registry location.

The reg.exe process exits with status 0x0, confirming successful execution, but we cannot verify from the telemetry whether the registry value was actually written.

## Assessment

This dataset provides excellent coverage of the process execution chain but fails to capture the core registry modification activity that defines T1112. For registry modification detection, this represents a common blind spot where process creation events are captured but the actual registry writes are missed due to configuration gaps.

The Security channel provides comprehensive process execution telemetry with command-line arguments, making it valuable for detecting suspicious registry tool usage. However, without registry write events, defenders cannot distinguish between successful and failed registry operations, nor can they see what values were actually modified.

This highlights the critical importance of comprehensive registry monitoring configuration, particularly for security-relevant registry paths like BitLocker policy locations.

## Detection Opportunities Present in This Data

1. **Registry Tool Command Line Detection**: Security EID 4688 captures `reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE"` with the specific UseAdvancedStartup modification, enabling detection of BitLocker policy tampering attempts.

2. **PowerShell Process Spawning Registry Tools**: Sysmon EID 1 shows PowerShell spawning cmd.exe which then spawns reg.exe, a common pattern for scripted registry modifications that merits investigation.

3. **Registry Tool Process Chain Analysis**: The powershell.exe → cmd.exe → reg.exe execution chain visible in both Security and Sysmon events provides a behavioral signature for scripted registry manipulation.

4. **Administrative Registry Path Targeting**: The command line targets `HKLM\SOFTWARE\Policies\Microsoft\FVE`, a high-value registry location that should trigger alerts when modified by non-administrative tools.

5. **PowerShell Process Access to Child Processes**: Sysmon EID 10 shows PowerShell accessing spawned processes with full rights (0x1FFFFF), indicating potential process manipulation that could accompany registry modification activities.
