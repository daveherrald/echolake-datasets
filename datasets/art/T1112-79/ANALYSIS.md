# T1112-79: Modify Registry — Modify UseTPMPIN Registry entry

## Technique Context

T1112 (Modify Registry) involves adversaries making changes to the Windows Registry to hide configuration information, remove information as a form of defense evasion, or establish persistence. Registry modifications are a staple of Windows environments and can affect system behavior, application settings, and security configurations. The detection community focuses heavily on monitoring registry changes to sensitive keys, particularly those related to security controls, startup mechanisms, and system policies.

This specific test targets the `UseTPMPIN` registry value under `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Full Volume Encryption), which controls BitLocker TPM PIN requirements. Modifying this setting could allow attackers to weaken disk encryption requirements or bypass certain BitLocker protections. Such changes to encryption policy settings are of particular interest to defenders as they can indicate attempts to reduce security controls.

## What This Dataset Contains

The dataset captures a successful registry modification operation with comprehensive telemetry across multiple data sources. The core action involves PowerShell spawning cmd.exe to execute reg.exe with the command line: `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 2 /f`.

Security Event 4688 shows the process creation chain: PowerShell (PID 4172) → cmd.exe (PID 9760) → reg.exe (PID 37388). The reg.exe command line clearly shows the registry modification attempt with the `/f` flag to force the operation without confirmation.

Sysmon captures rich process creation events (EID 1) for all three processes in the chain, including full command lines, process hashes, and integrity levels. Notably, Sysmon EID 1 events show the processes running as NT AUTHORITY\SYSTEM with System integrity level, and include process GUIDs that allow correlation across events.

Sysmon EID 10 (Process Access) events show PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), providing visibility into the parent-child process relationships. Additional Sysmon events include DLL loads (EID 7) showing Windows Defender components and .NET runtime libraries being loaded into PowerShell processes.

The PowerShell operational log contains only test framework boilerplate (Set-ExecutionPolicy Bypass and Set-StrictMode scriptblocks) without capturing the actual registry modification command.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual registry modification event that would normally be captured by Sysmon EID 13 (Registry Value Set). The sysmon-modular configuration may be filtering these events, or the registry change occurred too quickly to be captured in the collection window.

The dataset also doesn't contain any Windows Defender alerts or blocks, indicating the registry modification was allowed to complete. There are no Object Access audit events (4656/4658) that would show access to the registry key, likely because object auditing is disabled in the audit policy.

The Security log shows reg.exe exiting with status 0x0 (success), suggesting the registry modification completed successfully, but we lack direct evidence of the actual registry change.

## Assessment

This dataset provides excellent visibility into the process execution chain leading to registry modification but falls short on capturing the actual registry change itself. The Security and Sysmon process creation events offer strong detection opportunities for the technique, particularly the use of reg.exe with specific command-line patterns targeting sensitive registry locations.

The process telemetry is comprehensive and would support detection rules focused on process ancestry, command-line analysis, and suspicious registry tool usage. However, the absence of registry modification events (Sysmon EID 13) limits the dataset's value for building detections that focus on the actual registry changes rather than the tools used to make them.

For building robust T1112 detections, this dataset would benefit from registry modification logging or Object Access auditing to capture the actual registry value changes.

## Detection Opportunities Present in This Data

1. **Registry Tool Command Line Analysis** - Monitor for reg.exe executions with "add" operations targeting sensitive registry paths like "HKLM\SOFTWARE\Policies\Microsoft\FVE"

2. **Process Chain Analysis** - Detect PowerShell spawning cmd.exe which then spawns reg.exe, particularly when targeting policy-related registry keys

3. **Sensitive Registry Path Targeting** - Alert on registry operations against BitLocker/FVE policy keys that could weaken encryption controls

4. **Administrative Tool Abuse** - Monitor reg.exe usage with administrative privileges (System integrity level) for policy modifications

5. **Process Access Correlation** - Correlate Sysmon EID 10 process access events showing PowerShell accessing registry tools with suspicious command lines

6. **System-Level Registry Modifications** - Flag registry operations running as NT AUTHORITY\SYSTEM targeting security policy locations

7. **Command-Line Pattern Detection** - Identify reg.exe invocations with `/f` (force) flag combined with policy registry paths

8. **Parent Process Context** - Detect reg.exe spawned from non-administrative tools or unexpected parent processes like PowerShell or cmd.exe
