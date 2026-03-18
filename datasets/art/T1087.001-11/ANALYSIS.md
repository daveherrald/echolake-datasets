# T1087.001-11: Local Account — ESXi - Local Account Discovery via ESXCLI

## Technique Context

T1087.001 Local Account Discovery is a fundamental reconnaissance technique where attackers enumerate local user accounts on a system to understand available targets for lateral movement, privilege escalation, or persistence. The ESXCLI variant tested here attempts to discover local accounts on ESXi hypervisors using VMware's command-line management interface. This technique is particularly valuable in virtualized environments where compromising the hypervisor provides access to all hosted virtual machines. Detection engineering typically focuses on unusual account enumeration commands, unexpected network connections to hypervisor management interfaces, and the use of ESXi-specific tools from non-administrative workstations.

## What This Dataset Contains

This dataset captures an attempt to execute ESXi account discovery using the plink SSH client to connect to a remote ESXi host. The primary evidence appears in Security event 4688, which shows a cmd.exe process executing: `"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" -batch "atomic.local" -ssh -l root -pw "password" "esxcli system account list"`. 

The process chain shows PowerShell (PID 24588) spawning cmd.exe (PID 25500), which then creates a child cmd.exe process (PID 22840) for the echo command portion of the pipeline. Sysmon captures this chain with ProcessCreate events (EID 1) showing the command shell invocations. The dataset also includes a System Owner/User Discovery attempt via whoami.exe, likely for initial reconnaissance before the ESXi connection attempt.

Security events show all processes exiting with error codes - cmd.exe processes exit with status 0x1 and 0xFF, indicating the ESXi connection failed, which is expected since "atomic.local" is not a valid ESXi host in this test environment.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful ESXi connectivity or actual account enumeration results, as the target host "atomic.local" appears to be non-existent or unreachable. There are no network connection events (Sysmon EID 3) showing successful SSH connections, no DNS queries for the target host, and no file operations indicating that plink.exe was actually executed or that results were written anywhere.

The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual PowerShell script that orchestrated this test. The sysmon-modular configuration likely filtered out the plink.exe process creation since it's not in the known-suspicious LOLBins patterns, leaving only the cmd.exe wrapper processes visible.

## Assessment

This dataset provides moderate value for detection engineering focused on ESXi-specific reconnaissance attempts. The Security channel 4688 events with command-line logging capture the complete attack syntax, including credential information ("root" username, hardcoded password) and the specific ESXi command attempted. However, the failed execution limits the dataset's utility for understanding successful technique completion or post-exploitation artifacts.

The process tree captured in Sysmon shows how attackers might use command shell pipelines to orchestrate complex remote management tool invocations, even when the tools themselves don't generate Sysmon ProcessCreate events. The presence of both whoami.exe reconnaissance and the ESXi connection attempt provides insight into multi-stage enumeration workflows.

## Detection Opportunities Present in This Data

1. Command-line detection for esxcli commands executed via SSH clients (plink.exe, ssh.exe) with account enumeration parameters like "system account list"
2. Process chain analysis identifying PowerShell spawning cmd.exe processes that invoke SSH/remote management tools
3. Hardcoded credential detection in command lines containing "-l" (username) and "-pw" (password) parameters for SSH connections
4. Behavioral analysis of reconnaissance sequences combining local user discovery (whoami.exe) with remote system enumeration attempts
5. Network tool invocation patterns where administrative tools like plink.exe are called with batch processing flags from non-interactive contexts
6. ESXi-specific command detection focusing on "esxcli system" commands that retrieve sensitive configuration or account information
7. Failed process execution correlation where SSH clients exit with error codes, potentially indicating scanning or connection attempts against non-existent infrastructure
