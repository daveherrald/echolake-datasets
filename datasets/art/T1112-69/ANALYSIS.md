# T1112-69: Modify Registry — RDP Authentication Level Override

## Technique Context

T1112 (Modify Registry) is a fundamental technique where adversaries manipulate Windows registry values to alter system behavior, maintain persistence, or evade defenses. This specific test modifies the RDP authentication level override setting, which controls how Terminal Services validates client authentication. By setting `AuthenticationLevelOverride` to 0, attackers can potentially weaken RDP authentication requirements, allowing connections even when certificate validation fails. This technique is particularly relevant for lateral movement scenarios where attackers want to establish RDP connections to compromised systems while bypassing normal authentication controls. Detection engineers focus on monitoring registry modifications to security-relevant keys, especially those affecting authentication mechanisms, network services, and system configurations.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed through PowerShell and cmd.exe. The core technique evidence appears in Security event 4688, which shows the command line: `"cmd.exe" /c reg add "HKCU\Software\Microsoft\Terminal Server Client" /v AuthenticationLevelOverride /t REG_DWORD /d 0 /f`. The process chain is clear: powershell.exe (PID 14700) → cmd.exe (PID 42716) → reg.exe (PID 37472).

Sysmon provides complementary process creation events (EIDs 1) for the cmd.exe and reg.exe processes, along with process access events (EID 10) showing PowerShell accessing the spawned processes with full access rights (0x1FFFFF). The dataset also contains typical PowerShell startup artifacts including .NET assembly loads and pipe creation events.

Security events show the complete process lifecycle with both creation (4688) and termination (4689) events, plus a token rights adjustment event (4703) showing PowerShell acquiring extensive system privileges including SeBackupPrivilege and SeRestorePrivilege.

## What This Dataset Does Not Contain

Notably absent are Sysmon registry modification events (EID 13), which would directly capture the registry value being set. This is a significant gap since registry modification is the core technique behavior. The sysmon-modular configuration may not be monitoring the specific registry path `HKCU\Software\Microsoft\Terminal Server Client`, or the events may have been filtered out.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual PowerShell commands that initiated the technique. There are no network-related events showing actual RDP connection attempts that would demonstrate the impact of the registry modification.

## Assessment

The dataset provides good process execution telemetry showing the command-line evidence of the registry modification attempt, but lacks the actual registry change confirmation. The Security channel's command-line logging is the primary detection value here, clearly showing the reg.exe execution with the specific registry path and value. However, without Sysmon EID 13 events, you cannot confirm the registry modification actually succeeded. The process chain telemetry is complete and would support process-based detections, but the missing registry monitoring significantly limits the dataset's utility for comprehensive registry modification detection.

## Detection Opportunities Present in This Data

1. **Registry modification via reg.exe command line** - Security EID 4688 with process command line containing "reg add" operations targeting Terminal Server Client authentication settings

2. **Suspicious process chain** - PowerShell spawning cmd.exe which spawns reg.exe, particularly when modifying authentication-related registry keys

3. **RDP authentication bypass indicators** - Command lines containing "AuthenticationLevelOverride" with value 0, indicating attempts to weaken RDP security

4. **Sysmon process creation for registry tools** - EID 1 events for reg.exe execution with rule matching T1012 (Query Registry) technique

5. **Process access patterns** - Sysmon EID 10 showing PowerShell accessing spawned processes with full privileges, indicating programmatic process control

6. **Privilege escalation context** - Security EID 4703 showing PowerShell acquiring extensive system privileges before registry modifications
