# T1112-12: Modify Registry — Disable Windows Task Manager application

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify the Windows Registry to alter system configuration, disable security controls, or maintain persistence. This specific test focuses on disabling Task Manager through the `DisableTaskmgr` registry value, a common technique used by malware to prevent users from terminating malicious processes or analyzing running tasks. Attackers frequently target this setting because Task Manager is a primary tool for incident response and system analysis. The detection community focuses on monitoring registry modifications to policy-related keys, particularly those that disable security tools or administrative utilities.

## What This Dataset Contains

This dataset captures a clean execution of the registry modification technique through the following process chain:

1. **PowerShell execution** - Security event 4688 shows PowerShell launching with command-line auditing
2. **Command shell invocation** - Sysmon EID 1 captures `cmd.exe` execution: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskmgr /t REG_DWORD /d 1 /f`
3. **Registry utility execution** - Sysmon EID 1 shows `reg.exe` with the actual registry modification command: `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskmgr /t REG_DWORD /d 1 /f`
4. **Registry modification** - Sysmon EID 13 captures the actual registry write: `HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\policies\system\DisableTaskmgr` set to `DWORD (0x00000001)`

The technique executed successfully with exit status 0x0 for all processes. Security events provide complete process creation and termination coverage with full command lines, while Sysmon captures the critical registry modification event.

## What This Dataset Does Not Contain

The dataset lacks some expected artifacts due to configuration and context:
- No PowerShell script block logging of the actual test command (only test framework boilerplate Set-StrictMode and Set-ExecutionPolicy events in EID 4104)
- The registry write targets `HKU\.DEFAULT` rather than a user-specific hive because the test runs as NT AUTHORITY\SYSTEM
- No file system artifacts beyond PowerShell startup profile creation
- No network activity since this is a local registry modification

## Assessment

This dataset provides excellent coverage for detecting T1112 registry modification techniques. The combination of Security 4688 process creation events with command-line logging and Sysmon EID 13 registry modification events creates comprehensive detection opportunities. The process chain from PowerShell → cmd.exe → reg.exe is well-documented, and the registry write event contains all necessary details for building robust detections. The technique's successful execution without security product interference makes this particularly valuable for understanding the complete attack flow.

## Detection Opportunities Present in This Data

1. **Command-line detection for reg.exe modifying DisableTaskmgr** - Security EID 4688 with command line containing both `reg add` and `DisableTaskmgr` parameters
2. **Registry write monitoring for Task Manager disabling** - Sysmon EID 13 targeting `*\policies\system\DisableTaskmgr` with DWORD value 1
3. **Process chain analysis** - PowerShell spawning cmd.exe which spawns reg.exe for registry modification
4. **Suspicious registry path targeting** - Any writes to `*\CurrentVersion\Policies\System\` with administrative bypass values
5. **Command shell execution for registry operations** - cmd.exe with `/c` parameter executing registry commands
6. **Administrative utility abuse** - reg.exe usage with policy modification parameters in automated scripts
