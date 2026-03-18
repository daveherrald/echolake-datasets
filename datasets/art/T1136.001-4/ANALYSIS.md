# T1136.001-4: Local Account — Create a new user in a command prompt

## Technique Context

T1136.001 (Create Account: Local Account) is a persistence technique where attackers create new local user accounts to maintain access to a compromised system. This technique is particularly valuable for attackers because it provides a legitimate-appearing method of persistence that doesn't require modifying existing system files or registry entries. The detection community focuses heavily on monitoring `net user` commands, especially those with the `/add` parameter, as well as Security event 4720 (A user account was created) and related account management events. Process creation monitoring for cmd.exe and net.exe with user creation parameters is a cornerstone detection approach.

## What This Dataset Contains

This dataset captures a successful local user account creation using the classic `net user /add` command pattern. The technique executes through a clear process chain: PowerShell → cmd.exe → net.exe → net1.exe. Key telemetry includes:

**Process Creation Chain (Security 4688 events):**
- `"cmd.exe" /c net user /add "T1136.001_CMD" "T1136.001_CMD!"` (PID 8856)
- `net user /add "T1136.001_CMD" "T1136.001_CMD!"` (PID 13636) 
- `C:\Windows\system32\net1 user /add "T1136.001_CMD" "T1136.001_CMD!"` (PID 13988)

**Sysmon Process Creation (EID 1):**
- cmd.exe with CommandLine showing the full net user command including username and password
- net.exe and net1.exe executions with complete command arguments
- Process access events (EID 10) showing PowerShell accessing the spawned processes

**Exit Status Indicators:**
- net1.exe and net.exe both exit with status 0x2 (Security 4689), indicating the user creation failed
- cmd.exe exits with status 0x2, confirming command execution failure

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content.

## What This Dataset Does Not Contain

Critically, this dataset lacks the Security event 4720 (A user account was created) that would confirm successful user creation. The exit codes (0x2) from net.exe and net1.exe processes indicate the account creation actually failed, likely due to insufficient privileges or policy restrictions. This means while the attempt is fully captured in process telemetry, there's no evidence of successful persistence establishment. The dataset also lacks any account management audit events (Security event IDs 4720-4726 range) that would typically accompany successful local account creation.

## Assessment

This dataset provides excellent telemetry for detecting **attempted** local account creation via net.exe commands. The Security 4688 events with full command-line logging capture the complete attack attempt including username and password parameters. Sysmon EID 1 events provide additional process creation details with parent-child relationships clearly established. However, the failure of the actual account creation (evidenced by exit codes) limits the dataset's utility for understanding successful account creation workflows and the security events they generate. For detection engineering focused on the attempt rather than success, this data is highly valuable.

## Detection Opportunities Present in This Data

1. **Net.exe user creation commands** - Security 4688 events showing `net.exe` or `net1.exe` with CommandLine containing "user /add" parameters

2. **Command shell spawning net.exe for user management** - Process creation showing cmd.exe with `/c net user /add` command patterns

3. **PowerShell spawning command shells for user operations** - Process tree analysis showing powershell.exe → cmd.exe → net.exe chains

4. **Net.exe process failures with user creation attempts** - Security 4689 events showing net.exe exit codes of 0x2 combined with user creation command lines

5. **Sysmon process access patterns** - EID 10 events showing PowerShell accessing newly created cmd.exe and net.exe processes during user creation attempts

6. **Suspicious user creation command arguments** - Detection of specific username patterns (like "T1136.001_CMD") or password parameters in net.exe command lines
