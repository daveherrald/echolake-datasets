# T1021.002-4: SMB/Windows Admin Shares — Execute command writing output to local Admin Share

## Technique Context

T1021.002 (SMB/Windows Admin Shares) is a lateral movement technique where attackers leverage administrative network shares (like ADMIN$, C$, IPC$) to execute commands or transfer files on remote systems. This technique is fundamental to Windows-based lateral movement, as these shares are enabled by default on Windows systems and provide direct access to system directories when the attacker has appropriate credentials.

The detection community focuses on monitoring SMB connections to administrative shares, unusual file writes to these locations, command execution patterns that involve UNC paths, and the characteristic process chains that emerge when commands are executed remotely via these shares. This specific test variant executes a command locally but redirects output to the local ADMIN$ share, simulating the file operations that occur during actual lateral movement scenarios.

## What This Dataset Contains

The dataset captures a PowerShell-initiated command execution that writes output to the local ADMIN$ share. The core activity is visible in Security event 4688: `"cmd.exe" /c cmd.exe /Q /c hostname 1> \\127.0.0.1\ADMIN$\output.txt 2>&1`, showing command output redirection to a UNC path targeting the local administrative share.

The process chain shows PowerShell (PID 3468) spawning cmd.exe (PID 3004), which then spawns a second cmd.exe (PID 7268) to execute the hostname command. Sysmon event ID 1 captures both cmd.exe creations with rule matches for "Windows Command Shell" technique T1059.003.

A critical file operation is captured in Sysmon event ID 11, showing the System process creating `C:\Windows\output.txt` with a rule match for "Services File Permissions Weakness" (T1574.010). This represents the actual file write that occurs when output is redirected to \\127.0.0.1\ADMIN$.

Additional process access events (Sysmon ID 10) show PowerShell accessing both the whoami.exe and cmd.exe processes with extensive access rights (0x1FFFFF), indicating the parent process monitoring or managing its child processes.

The PowerShell channel contains only test framework boilerplate events (Set-ExecutionPolicy Bypass and Set-StrictMode scriptblocks) with no technique-specific PowerShell command logging.

## What This Dataset Does Not Contain

The dataset lacks network-level SMB telemetry that would typically accompany true lateral movement via admin shares. No SMB connection events, share access logs, or network authentication events are present since this test executes against the local system.

Missing are any authentication events (like 4624/4625) or explicit share access events (4656/4658) that would indicate actual network share access patterns. The UNC path resolution happens locally, so network-based detection opportunities are not represented.

The Sysmon configuration's include-mode filtering means some intermediate processes may not be captured if they don't match known-suspicious patterns, though the key cmd.exe processes are present due to their classification as potential LOLBins.

## Assessment

This dataset provides valuable telemetry for detecting the file operations and command patterns associated with admin share usage, even though it simulates local execution rather than true lateral movement. The combination of Security 4688 events with command-line logging and Sysmon process creation events offers strong coverage of the execution chain.

The file creation event showing output.txt being written to C:\Windows\ (the local resolution of ADMIN$) is particularly valuable, as it demonstrates how admin share file operations appear in endpoint telemetry. However, the dataset's limitation to local execution means it doesn't capture the network-based indicators that are crucial for detecting actual lateral movement scenarios.

For detection engineering purposes, this data is most useful for understanding the endpoint-side artifacts of admin share usage rather than the network-based lateral movement patterns.

## Detection Opportunities Present in This Data

1. **Command line redirection to UNC admin share paths** - Monitor Security 4688 events for command lines containing `> \\<host>\ADMIN$\` or similar administrative share redirections

2. **Process chain analysis for cmd.exe spawning patterns** - Detect PowerShell spawning cmd.exe which spawns additional cmd.exe processes, particularly with /Q and /c flags

3. **File creation in Windows system directories via System process** - Monitor Sysmon EID 11 for System process creating files in C:\Windows\ that may indicate admin share write operations

4. **Process access patterns indicating child process management** - Alert on processes accessing newly created cmd.exe processes with full access rights (0x1FFFFF)

5. **Administrative share path resolution** - Correlate command lines containing localhost/127.0.0.1 admin share references with subsequent file creation events in corresponding local directories

6. **Hostname enumeration combined with output redirection** - Detect hostname, whoami, or other reconnaissance commands with output redirected to UNC paths as potential lateral movement preparation
