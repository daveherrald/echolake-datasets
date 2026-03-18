# T1059.001-21: PowerShell — SOAPHound - Dump BloodHound Data

## Technique Context

T1059.001 (PowerShell) is a foundational execution technique where attackers leverage PowerShell to run commands, scripts, and executables. SOAPHound is a C# tool that uses SOAP queries to enumerate Active Directory objects and extract data for BloodHound analysis, providing detailed information about domain trusts, users, groups, and attack paths. Unlike SharpHound which uses LDAP, SOAPHound leverages Active Directory Web Services (ADWS) via SOAP protocol, potentially offering better stealth characteristics. The detection community focuses on PowerShell command-line arguments, script block content, process relationships, and network connections to domain controllers.

## What This Dataset Contains

This dataset captures a PowerShell execution launching SOAPHound with full credentials and targeting parameters. The Security channel shows the complete process chain with Security 4688 events capturing the PowerShell command line: `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $env:USERNAME --password P@ssword1 --domain $env:USERDOMAIN --dc 10.0.1.14 --bhdump --cachefilename c:\temp\cache.txt --outputdirectory c:\temp\test2}`. 

The PowerShell channel (37 events) contains the actual script block showing the SOAPHound execution command with all parameters exposed: `& {C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $env:USERNAME --password P@ssword1 --domain $env:USERDOMAIN --dc 10.0.1.14 --bhdump --cachefilename c:\temp\cache.txt --outputdirectory c:\temp\test2}`. Most other PowerShell events are test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass).

Sysmon captures the full process tree: parent PowerShell (PID 44320) spawning child PowerShell (PID 43424) with the SOAPHound command line, plus a whoami.exe execution (PID 44220). Multiple Sysmon 7 events show .NET framework loading (mscoree.dll, mscoreei.dll, clr.dll) and System.Management.Automation.ni.dll loading, indicating PowerShell engine initialization. Sysmon 10 events capture process access from PowerShell to both whoami.exe and the child PowerShell process. File creation events (Sysmon 11) show PowerShell profile initialization.

## What This Dataset Does Not Contain

Critically missing is the actual SOAPHound.exe execution. No Sysmon ProcessCreate event exists for SOAPHound.exe itself, indicating either the sysmon-modular config didn't match SOAPHound as a suspicious binary, or Windows Defender blocked the execution before the process could start. The Security 4688 events show all PowerShell processes completed with exit status 0x0, suggesting clean termination rather than access denied.

No network connection events (Sysmon 3) are present despite SOAPHound requiring LDAPS/SOAP connections to the specified domain controller (10.0.1.14). This absence, combined with the missing SOAPHound process creation, strongly suggests the tool was blocked before network activity occurred. No file writes to the specified output directory (c:\temp\test2) or cache file (c:\temp\cache.txt) are captured, confirming SOAPHound didn't execute successfully.

## Assessment

This dataset provides excellent visibility into PowerShell-based tool launching attempts but limited insight into SOAPHound's actual execution behavior. The Security and PowerShell channels deliver complete command-line visibility with full parameter exposure including credentials, target IP, and output paths. The process telemetry clearly shows the execution chain and .NET framework loading patterns typical of PowerShell-hosted tools.

However, the dataset's value is limited by the apparent blocking of SOAPHound execution. For building detections focused on PowerShell delivery mechanisms, command-line patterns, and initial execution attempts, this data is highly valuable. For understanding SOAPHound's network behavior, AD enumeration patterns, or file artifacts, this dataset provides no insight.

## Detection Opportunities Present in This Data

1. **PowerShell command-line detection** - Security 4688 and PowerShell 4104 events contain the full SOAPHound command line with hardcoded credentials, domain controller IP, and output paths for static signature matching

2. **Credential exposure in PowerShell** - Both command line and script block contain cleartext password "P@ssword1" visible in multiple event sources

3. **Active Directory enumeration tool signatures** - Command line contains SOAPHound-specific parameters (--bhdump, --cachefilename) and the executable path pattern "atomics\T1059.001\bin\SOAPHound.exe"

4. **PowerShell process spawning patterns** - Sysmon 1 events show PowerShell spawning child PowerShell processes, a common pattern for script-based tool execution

5. **Domain controller targeting** - Command line explicitly specifies DC IP address (10.0.1.14) for correlation with network monitoring

6. **BloodHound data collection indicators** - Parameters like --bhdump and output directory paths (c:\temp\test2) indicate BloodHound data preparation activities

7. **Environment variable usage in PowerShell** - Script blocks show $env:USERNAME and $env:USERDOMAIN usage patterns common in reconnaissance scripts
