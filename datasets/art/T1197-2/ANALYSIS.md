# T1197-2: BITS Jobs — Bitsadmin Download (PowerShell)

## Technique Context

T1197 BITS Jobs is a dual-use technique attackers leverage for both defense evasion and persistence. The Background Intelligent Transfer Service (BITS) is a legitimate Windows component designed for asynchronous file transfers that can operate during system downtime. Attackers abuse BITS because it provides several advantages: downloads continue across reboots and network interruptions, BITS jobs can be configured to execute programs upon completion, and the service runs with high privileges while generating minimal network monitoring alerts. The detection community primarily focuses on monitoring BITS job creation via PowerShell cmdlets, WMI objects, bitsadmin.exe command lines, and the loading of BITS-related DLLs. This particular test demonstrates PowerShell's Start-BitsTransfer cmdlet to download a file from GitHub, representing a common initial access or data staging technique.

## What This Dataset Contains

This dataset captures a PowerShell-based BITS transfer execution with comprehensive telemetry. Security event 4688 shows the PowerShell process creation with command line `"powershell.exe" & {Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md -Destination $env:TEMP\bitsadmin2_flag.ps1}`. PowerShell module logging (4103) reveals the Start-BitsTransfer cmdlet invocation with parameters including the GitHub source URL and local destination. The dataset includes BITS service startup telemetry in System event 7040 showing the service changing from "demand start to auto start". Sysmon captures critical BITS-specific DLL loads including BitsProxy.dll in both PowerShell (PID 37328) and svchost.exe (PID 9040) processes. DNS resolution for raw.githubusercontent.com is logged in Sysmon event 22. File creation events show BITS temporary files like `C:\Windows\Temp\BIT7526.tmp` being created by svchost.exe. The dataset also contains .NET compilation artifacts as PowerShell's Add-Type cmdlet compiles C# code for the BitsTransfer module, including csc.exe and cvtres.exe process creation.

## What This Dataset Does Not Contain

The dataset lacks explicit BITS job management events that would typically be found in Microsoft-Windows-Bits-Client/Operational logs, which are not included in the collection. There are no ETW events from the BITS provider that would show job lifecycle details like creation, completion, or error states. The actual HTTP request details for the file download are not captured in network logs. Process access events show PowerShell accessing child processes but don't capture direct BITS API calls. While file creation events show BITS temporary files, the final movement of the downloaded content to the destination path isn't explicitly logged. Registry modifications related to BITS job persistence are not present, likely because this was a foreground transfer that completed immediately rather than a persistent background job.

## Assessment

This dataset provides strong coverage for detecting PowerShell-based BITS abuse through multiple complementary data sources. The combination of Security 4688 command line logging, PowerShell module logging, and Sysmon DLL load events creates a robust detection foundation. The BitsProxy.dll loading events are particularly valuable as they provide a reliable indicator of BITS activity that's difficult to bypass. DNS logging adds network context that can help identify suspicious download sources. However, the dataset would be significantly stronger with BITS client operational logs and more detailed network capture showing the actual HTTP transfer. The heavy presence of .NET compilation artifacts might create some detection complexity, but these are legitimate components of PowerShell's BITS functionality.

## Detection Opportunities Present in This Data

1. **PowerShell Start-BitsTransfer cmdlet detection** - Monitor PowerShell operational log event 4103 for Start-BitsTransfer cmdlet invocations, particularly with external URLs as source parameters.

2. **BITS proxy DLL loading in unexpected processes** - Alert on Sysmon event 7 showing BitsProxy.dll or qmgrprxy.dll loading in processes other than typical BITS service contexts.

3. **Suspicious command line patterns** - Detect Security event 4688 PowerShell processes with command lines containing "Start-BitsTransfer" and external HTTP/HTTPS URLs.

4. **BITS service startup correlation** - Monitor System event 7040 for Background Intelligent Transfer Service changing to auto start, especially when correlated with recent PowerShell activity.

5. **DNS queries to code repositories** - Flag Sysmon event 22 DNS queries for code hosting domains (github.com, githubusercontent.com, etc.) from system processes like svchost.exe.

6. **BITS temporary file creation patterns** - Monitor Sysmon event 11 for file creation in Windows\Temp with naming patterns like "BIT*.tmp" by svchost.exe processes.

7. **PowerShell process spawning with BITS-related command lines** - Correlate parent PowerShell processes with child processes showing BITS-related arguments or URLs in command lines.

8. **Unusual network destinations from BITS processes** - Monitor network connections from svchost.exe processes running BITS service to external domains for potential data exfiltration or malware downloads.
