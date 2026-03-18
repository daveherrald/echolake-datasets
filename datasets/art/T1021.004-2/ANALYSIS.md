# T1021.004-2: SSH — ESXi - Enable SSH via VIM-CMD

## Technique Context

T1021.004 focuses on SSH as a lateral movement technique, where adversaries leverage legitimate SSH connections to move between systems in compromised environments. This specific test simulates an attacker with access to a Windows system attempting to enable SSH on a remote ESXi host using VMware's vim-cmd utility through PuTTY's command-line SSH client (plink.exe). This represents a realistic attack scenario where adversaries compromise Windows workstations to manage virtualization infrastructure, potentially expanding their foothold across virtual environments. The detection community typically focuses on monitoring SSH client usage from unexpected systems, credential-based authentication attempts, and administrative commands executed over SSH connections.

## What This Dataset Contains

The dataset captures a PowerShell-initiated SSH connection attempt using plink.exe to execute a vim-cmd command on a remote ESXi host. The primary technique evidence appears in Security event 4688, which shows the command line: `"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" -batch "atomic.local" -ssh -l root -pw "password" "vim-cmd hostsvc/enable_ssh"`. This reveals the full SSH connection attempt with embedded credentials and the specific ESXi management command.

The process chain shows PowerShell (PID 6296) spawning cmd.exe (PID 6216), which then creates a child cmd.exe process (PID 7584) to handle the echo command portion of the pipe. Sysmon EID 1 events capture both cmd.exe process creations with their full command lines. The dataset also includes a whoami.exe execution (Sysmon EID 1, Security EID 4688) showing system reconnaissance activity.

Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with PROCESS_ALL_ACCESS permissions (0x1FFFFF), indicating the parent process monitoring its children. Multiple PowerShell instances are present, evidenced by three different ProcessGuid values and corresponding .NET runtime loading events (EID 7).

## What This Dataset Does Not Contain

Critically missing is the actual plink.exe process creation and execution. Despite the command line showing plink.exe being invoked, no Sysmon EID 1 or Security EID 4688 events capture this process, indicating the SSH client either failed to start or was blocked. The cmd.exe parent process exits with status 0xFF (255), suggesting command execution failure.

No network connection events (Sysmon EID 3) are present, confirming no outbound SSH connection was established to the target "atomic.local" system. The absence of DNS resolution events (Sysmon EID 22) indicates no hostname lookup occurred for the target. Missing are any authentication-related Security events (4624/4625) that would typically accompany successful SSH connections.

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass commands) with no script blocks showing the actual test implementation, limiting visibility into the PowerShell execution context.

## Assessment

This dataset provides excellent command-line evidence for SSH client invocation attempts but limited visibility into execution outcomes. The Security channel with command-line auditing captures the complete attack technique including credentials and target commands, making it highly valuable for detection engineering. The presence of embedded plaintext credentials in the command line makes this particularly useful for credential exposure detection scenarios.

However, the apparent failure of plink.exe to execute reduces the dataset's utility for understanding successful SSH lateral movement patterns. The lack of network telemetry limits its effectiveness for detecting actual SSH connections, making it more suitable for detecting attempt-based indicators rather than successful lateral movement.

## Detection Opportunities Present in This Data

1. **SSH Client Command Line Detection** - Monitor Security EID 4688 and Sysmon EID 1 for plink.exe, ssh.exe, or other SSH clients with command-line parameters indicating remote connections
2. **Embedded Credential Exposure** - Detect command lines containing SSH authentication parameters like "-l", "-pw", or password strings in plaintext
3. **VMware ESXi Management Commands** - Alert on "vim-cmd" usage in command lines, particularly hostsvc/enable_ssh or other service manipulation commands  
4. **Suspicious Process Chains** - Monitor PowerShell spawning cmd.exe that invokes SSH clients, indicating potential lateral movement preparation
5. **SSH Service Manipulation** - Detect attempts to enable SSH services on remote systems through command-line utilities
6. **Piped Command Execution** - Identify command lines using pipes (|) to feed input to SSH clients, often used to bypass interactive authentication
7. **Process Access Monitoring** - Track PowerShell processes accessing SSH client processes with high privileges (0x1FFFFF), indicating potential process injection or monitoring
8. **Failed SSH Client Execution** - Monitor for cmd.exe processes exiting with error codes (0xFF) after attempting to invoke SSH clients, indicating blocked or failed attempts
