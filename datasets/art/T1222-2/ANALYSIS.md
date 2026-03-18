# T1222-2: File and Directory Permissions Modification — Enable Local and Remote Symbolic Links via reg.exe

## Technique Context

T1222 (File and Directory Permissions Modification) involves adversaries altering file or directory permissions to circumvent security controls or enable persistence. This specific test focuses on symbolic link evaluation policies, which control how Windows handles symbolic links across local and remote boundaries. The `SymlinkRemoteToLocalEvaluation` and `SymlinkRemoteToRemoteEvaluation` registry keys control whether symbolic links can traverse security boundaries — a configuration that attackers may abuse to access files in restricted locations or perform privilege escalation. The detection community primarily focuses on registry modifications to filesystem security policies, use of reg.exe for privilege manipulation, and command-line patterns that modify symbolic link evaluation settings.

## What This Dataset Contains

The dataset captures a successful symbolic link policy modification executed via PowerShell and reg.exe. Security event 4688 shows cmd.exe spawning with the command line `"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v SymlinkRemoteToLocalEvaluation /t REG_DWORD /d "1" /f & reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v SymlinkRemoteToRemoteEvaluation /t REG_DWORD /d "1" /f`. Two subsequent reg.exe process creations are captured with their specific command lines: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v SymlinkRemoteToLocalEvaluation /t REG_DWORD /d "1" /f` and `reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v SymlinkRemoteToRemoteEvaluation /t REG_DWORD /d "1" /f`. Sysmon captures these same process creations (EID 1) with full command lines and process relationships showing PowerShell → cmd.exe → reg.exe chains. All processes exit with status 0x0, indicating successful execution. The technique runs under NT AUTHORITY\SYSTEM privileges.

## What This Dataset Does Not Contain

The dataset lacks registry modification events (Sysmon EID 13) showing the actual registry value changes, as the Sysmon configuration doesn't capture registry events. Windows Security events for object access (4663) are not present since object access auditing is disabled. The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy Bypass`) without the actual technique script content. No network activity or file operations are captured because this technique only modifies registry values. Process access events (Sysmon EID 10) are captured but don't provide direct evidence of the registry modifications themselves.

## Assessment

This dataset provides good coverage for process-based detection of symbolic link policy modification. The Security channel delivers complete process creation chains with full command lines, making it excellent for detecting reg.exe usage patterns targeting filesystem security policies. The PowerShell → cmd.exe → reg.exe process lineage is clearly visible in both Security 4688 events and Sysmon EID 1. However, the absence of registry modification telemetry limits the ability to detect the actual policy changes or build detections based on registry value monitoring. The technique executes successfully under SYSTEM privileges, providing realistic telemetry for enterprise detection scenarios.

## Detection Opportunities Present in This Data

1. **Registry Tool Command Line Detection** - Monitor Security 4688 or Sysmon EID 1 for reg.exe processes with command lines containing "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" and specific value names like "SymlinkRemoteToLocalEvaluation" or "SymlinkRemoteToRemoteEvaluation"

2. **Symbolic Link Policy Modification** - Detect reg.exe processes modifying filesystem control registry keys with `/v` parameters matching symbolic link evaluation settings and `/d "1"` enabling these policies

3. **Chained Process Execution** - Alert on PowerShell spawning cmd.exe which then spawns reg.exe, particularly when targeting HKLM\SYSTEM registry hives with filesystem-related modifications

4. **Privilege Escalation Preparation** - Monitor for registry modifications that enable symbolic link traversal across security boundaries, which may indicate preparation for privilege escalation or defense evasion

5. **Administrative Tool Abuse** - Detect legitimate administrative tools (reg.exe) being used to modify security-relevant filesystem policies, especially when executed through script interpreters like PowerShell
