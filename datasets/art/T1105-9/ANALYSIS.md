# T1105-9: Ingress Tool Transfer — Windows - BITSAdmin BITS Download

## Technique Context

T1105 (Ingress Tool Transfer) represents adversaries' need to bring tools and payloads into target environments to support their operations. BITSAdmin is a legitimate Windows utility that interfaces with the Background Intelligent Transfer Service (BITS), originally designed for efficient file transfers with bandwidth throttling and resume capabilities. Attackers commonly abuse BITSAdmin because it's a signed Microsoft binary (making it a "Living off the Land" technique), generates minimal network suspicious activity, and can download files with built-in retry mechanisms. The detection community focuses on monitoring BITSAdmin command-line usage, unusual download sources, and the correlation between BITSAdmin execution and subsequent malicious activity.

## What This Dataset Contains

This dataset captures a successful BITSAdmin file download execution with rich telemetry across multiple data sources:

**Security Event 4688** shows the complete process execution chain: PowerShell (PID 12836) spawning `"cmd.exe" /c C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt %temp%\Atomic-license.txt`, followed by the actual BITSAdmin execution with command line `C:\Windows\System32\bitsadmin.exe /transfer qcxjb7 /Priority HIGH https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt C:\Windows\TEMP\Atomic-license.txt`.

**Sysmon Event 1** (ProcessCreate) captures both the cmd.exe wrapper (PID 25880) and the BITSAdmin process (PID 9856) with full command-line details, process GUIDs, and parent-child relationships.

**Sysmon Event 7** (ImageLoad) shows BITSAdmin loading `C:\Windows\System32\BitsProxy.dll`, which is the core BITS functionality library.

**Sysmon Event 22** (DNSQuery) captures the DNS resolution for `raw.githubusercontent.com` by svchost.exe (the BITS service process).

**Sysmon Event 11** (FileCreate) shows the creation of temporary BITS transfer files (`C:\Windows\Temp\BITEAA1.tmp`) by the BITS service (svchost.exe PID 9364).

**Security Event 4689** confirms successful process termination with exit status 0x0 for BITSAdmin, indicating successful completion.

The PowerShell channel contains only execution policy bypass commands and error handling boilerplate, with no technique-specific content.

## What This Dataset Does Not Contain

The dataset lacks several telemetry elements that would strengthen detection coverage. There are no Sysmon Event 3 (NetworkConnect) events showing the actual HTTPS connection from the BITS service to the download source, though this may be due to the sysmon-modular configuration filtering. The final downloaded file (`C:\Windows\TEMP\Atomic-license.txt`) is not captured in Sysmon Event 11, suggesting the file creation occurred after the collection window or was filtered. Windows Event Log channels specific to BITS operations (such as Microsoft-Windows-Bits-Client/Operational) are not included in this dataset, which would provide BITS job creation, progress, and completion events with transfer details.

## Assessment

This dataset provides excellent coverage for detecting BITSAdmin abuse through process creation monitoring and command-line analysis. The Security 4688 and Sysmon 1 events contain the critical indicators needed for detection: the BITSAdmin binary execution, complete command-line arguments including the download URL, and the process ancestry showing the technique's context within a PowerShell execution chain. The presence of DNS queries and BITS-specific DLL loading provides additional corroborating evidence. However, the lack of network connection details and BITS service logs limits the dataset's utility for detecting more sophisticated BITS abuse scenarios or understanding the full scope of data transferred.

## Detection Opportunities Present in This Data

1. **BITSAdmin Process Creation**: Monitor Security 4688 and Sysmon 1 for `bitsadmin.exe` execution with `/transfer` parameter, especially when spawned from unexpected parent processes like PowerShell or cmd.exe rather than administrative tools.

2. **Suspicious Download URLs**: Analyze BITSAdmin command lines for downloads from external domains, particularly code hosting sites like GitHub, Pastebin, or other file sharing services that don't match expected administrative use cases.

3. **PowerShell-to-BITSAdmin Process Chain**: Detection of PowerShell spawning cmd.exe which then executes BITSAdmin indicates potential scripted download automation, a common attack pattern.

4. **BITS Service File Creation**: Monitor Sysmon 11 events from svchost.exe creating temporary files with "BIT" prefixes in system temporary directories, indicating active BITS transfers.

5. **DNS Query Correlation**: Correlate DNS queries for suspicious domains with subsequent BITSAdmin executions to identify potential download operations, even when network connection logs are unavailable.

6. **BITSProxy DLL Loading**: Sysmon 7 events showing BITSAdmin loading BitsProxy.dll can serve as an additional indicator of BITS functionality being actively used.

7. **High-Priority Transfer Detection**: Monitor for `/Priority HIGH` parameter usage in BITSAdmin commands, which may indicate urgency in malicious file transfers to avoid detection windows.
