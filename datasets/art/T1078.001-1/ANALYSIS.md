# T1078.001-1: Default Accounts — Default Accounts - Enable Guest account with RDP capability and admin privileges

## Technique Context

T1078.001 (Default Accounts) involves adversaries using built-in default accounts to maintain access to systems. The Guest account is a prime target as it's disabled by default on most systems but can be easily overlooked once enabled. Attackers commonly enable the Guest account, set a password, add it to privileged groups (Administrators, Remote Desktop Users), and configure RDP access to establish persistent remote access with elevated privileges.

This technique spans multiple tactics: Initial Access (gaining entry through enabled default accounts), Persistence (maintaining access via the Guest account), Privilege Escalation (adding Guest to Administrators), and Defense Evasion (using a legitimate built-in account that may evade detection). Detection engineering typically focuses on monitoring Guest account modifications, group membership changes, RDP configuration changes, and authentication events involving default accounts.

## What This Dataset Contains

This dataset captures a comprehensive execution of Guest account enabling and privilege escalation. The Security channel contains the complete command execution chain via EID 4688 events showing the cmd.exe batch execution: `"cmd.exe" /c net user guest /active:yes & net user guest Password123! & net localgroup Administrators guest /add & net localgroup "Remote Desktop Users" guest /add & reg add "hklm\system\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "hklm\system\CurrentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f`.

Sysmon provides detailed process creation events (EID 1) for each component command: whoami.exe for discovery, multiple net.exe/net1.exe executions for account manipulation (`net user guest /active:yes`, `net user guest Password123!`, `net localgroup Administrators guest /add`, `net localgroup "Remote Desktop Users" guest /add`), and reg.exe executions for Terminal Server configuration. 

Registry modifications are captured in Sysmon EID 13 showing `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` being set to 0x00000000 to enable RDP connections. Security EID 4703 shows token privilege adjustments for the PowerShell process executing the technique.

## What This Dataset Does Not Contain

Notably absent are Security EIDs 4720 (account created), 4722 (account enabled), 4724 (password reset), and 4732/4756 (group membership changes) that would typically accompany these account modifications. This suggests either the audit policy doesn't capture account management events or these specific operations didn't generate the expected audit events. 

The dataset lacks any successful logon events (4624) using the newly configured Guest account, meaning we only see the setup phase, not actual utilization of the backdoor. There are no network connection events showing RDP traffic or authentication attempts. The PowerShell channel contains only test framework boilerplate (Set-StrictMode calls and Set-ExecutionPolicy Bypass) rather than the actual technique execution commands.

## Assessment

This dataset provides excellent coverage of the technique execution phase through process creation and registry modification events. The command-line arguments in Security 4688 events offer complete visibility into what was attempted, while Sysmon EID 1 events provide granular process lineage showing the cmd.exe → net.exe → net1.exe execution patterns. The registry modification events confirm successful RDP configuration changes.

However, the dataset's primary weakness is the absence of account management audit events, which are crucial for detecting this technique in production environments. The lack of successful utilization events (logons, RDP connections) also limits its value for detection of the technique's post-exploitation phase. For building comprehensive detections, additional datasets with account management auditing enabled would be valuable.

## Detection Opportunities Present in This Data

1. **Suspicious batch command execution** - Security EID 4688 showing cmd.exe with long command lines containing multiple net.exe and reg.exe commands targeting Guest account and RDP configuration

2. **Guest account activation via net.exe** - Sysmon EID 1 process creation events for `net user guest /active:yes` and `net user guest Password123!` command patterns

3. **Privilege escalation via group addition** - Process creation events showing `net localgroup Administrators guest /add` and `net localgroup "Remote Desktop Users" guest /add`

4. **RDP configuration tampering** - Registry value modifications to `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` setting it to 0 (Sysmon EID 13)

5. **Process chain analysis** - PowerShell spawning cmd.exe which spawns multiple net.exe/net1.exe processes in rapid succession, indicating automated account manipulation

6. **Hardcoded password patterns** - Command lines containing what appears to be password setting (`Password123!`) for default accounts in process creation events

7. **Terminal Server registry modifications** - Multiple reg.exe processes targeting Terminal Server configuration keys for enabling remote access
