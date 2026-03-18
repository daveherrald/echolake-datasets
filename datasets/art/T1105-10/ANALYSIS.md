# T1105-10: Ingress Tool Transfer — Windows - PowerShell Download

## Technique Context

T1105 (Ingress Tool Transfer) represents one of the most fundamental command-and-control techniques, where adversaries bring tools or files from an external system into a compromised environment. This particular test focuses on PowerShell-based downloads using the .NET WebClient class, a classic approach that remains popular due to its simplicity and effectiveness. The detection community prioritizes this technique because it's often the first step in multi-stage attacks where initial access is followed by tool staging. Common variations include using PowerShell's Invoke-WebRequest, System.Net.WebClient, certutil, bitsadmin, or built-in Windows utilities. Detection efforts typically focus on process command lines containing download patterns, network connections to suspicious domains, and file creation events for downloaded payloads.

## What This Dataset Contains

This dataset captures a successful PowerShell download execution with comprehensive telemetry. The primary technique evidence appears in Security event 4688, showing PowerShell process creation with the command line `"powershell.exe" & {(New-Object System.Net.WebClient).DownloadFile(\"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt\", \"$env:TEMP\Atomic-license.txt\")}`. 

Sysmon provides rich complementary data including process creation (EID 1) with the same command line, DNS query resolution (EID 22) for "raw.githubusercontent.com" resolving to GitHub's CDN IPs, and file creation (EID 11) showing the successful download to `C:\Windows\Temp\Atomic-license.txt`. The PowerShell operational channel captures script block logging (EID 4104) with the WebClient instantiation and DownloadFile method call, plus command invocation logging (EID 4103) showing New-Object cmdlet execution.

Process lineage shows the test framework PowerShell (PID 16760) spawning the download PowerShell (PID 7876), then creating a whoami.exe process for reconnaissance. Multiple image load events (EID 7) document .NET runtime components and Windows Defender integration during PowerShell execution.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry - no Sysmon EID 3 events showing the actual HTTPS connection to GitHub's servers, likely because the sysmon-modular configuration may filter routine HTTPS connections. There are no Windows Defender detection alerts despite real-time protection being active, indicating this benign download didn't trigger behavioral detections. 

The DNS query event (EID 22) shows process GUID as all zeros and image as `<unknown process>`, suggesting it originated from a system process rather than directly from PowerShell. No registry modifications are captured, and there are no process access events related to the download itself (the EID 10 events relate to process injection detection rules, not the download).

## Assessment

This dataset provides excellent detection engineering value for PowerShell-based download scenarios. The multi-layered telemetry creates redundant detection opportunities - Security 4688 provides command line visibility even if Sysmon ProcessCreate is filtered, while PowerShell logging captures the actual method calls regardless of command line obfuscation. The successful file creation event confirms the download completed, and DNS telemetry enables network-based detection.

The data quality is high with complete process lineage, accurate timestamps, and detailed command line capture. While missing direct network connection telemetry limits some detection approaches, the combination of process, script, and file events provides robust coverage for this technique variant.

## Detection Opportunities Present in This Data

1. **PowerShell WebClient Download Pattern** - Detect Security EID 4688 or Sysmon EID 1 with command lines containing "New-Object.*WebClient.*DownloadFile" regex patterns

2. **PowerShell Script Block Analysis** - Monitor PowerShell EID 4104 events for script blocks containing "System.Net.WebClient" and "DownloadFile" method combinations

3. **Suspicious File Creation in Temp** - Alert on Sysmon EID 11 file creation events in temporary directories (`%TEMP%`, `C:\Windows\Temp`) by PowerShell processes

4. **DNS Query to Code Repositories** - Track Sysmon EID 22 DNS queries to known code hosting domains (github.com, githubusercontent.com, gitlab.com, etc.)

5. **PowerShell Process Chain Analysis** - Detect PowerShell spawning other PowerShell processes with download-related command lines, indicating potential staged execution

6. **New-Object Cmdlet Invocation** - Monitor PowerShell EID 4103 command invocation events for New-Object cmdlet with networking classes as parameters

7. **PowerShell Network Activity Correlation** - Correlate PowerShell process creation with subsequent DNS queries and file creation events within short time windows

8. **Command Line Entropy Analysis** - Calculate entropy scores for PowerShell command lines to detect obfuscated download commands while using this clean example as a baseline
