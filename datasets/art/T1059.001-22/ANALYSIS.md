# T1059.001-22: PowerShell — SOAPHound - Build Cache

## Technique Context

PowerShell execution (T1059.001) is a fundamental technique for both legitimate administration and adversary operations. SOAPHound is a .NET tool for Active Directory enumeration that queries domain controllers via ADWS (Active Directory Web Services) to build comprehensive attack path caches for tools like BloodHound. Unlike traditional LDAP-based enumeration tools, SOAPHound leverages SOAP/HTTP protocols, making it particularly useful for bypassing network-based detections focused on LDAP traffic. The detection community focuses on PowerShell script block logging, process creation with suspicious command lines, and the execution of reconnaissance tools that query Active Directory infrastructure.

## What This Dataset Contains

The dataset captures a complete PowerShell-based SOAPHound execution chain. Security event 4688 shows the critical PowerShell process creation with the full command line: `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $($env:USERNAME)@$($env:USERDOMAIN) --password P@ssword1 --dc 10.0.1.14 --buildcache --cachefilename c:\temp\cache.txt}`. PowerShell script blocks in event 4104 capture the exact execution: `& {C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $($env:USERNAME)@$($env:USERDOMAIN) --password P@ssword1 --dc 10.0.1.14 --buildcache --cachefilename c:\temp\cache.txt}`.

Sysmon provides rich process telemetry showing three PowerShell processes (PIDs 7840, 40932, 7444) with comprehensive .NET runtime loading events (EID 7). Process access events (EID 10) show PowerShell accessing child processes with full access rights (0x1FFFFF). The process chain shows the parent PowerShell (PID 40932) spawning the target PowerShell process (PID 7444) that executes the SOAPHound command. A whoami.exe process (PID 41332) is also captured, indicating system reconnaissance activity.

## What This Dataset Does Not Contain

Critically missing is any Sysmon ProcessCreate (EID 1) event for SOAPHound.exe itself, despite the command line clearly showing its intended execution. This absence suggests either the sysmon-modular configuration filtered it out (SOAPHound.exe not matching known-suspicious patterns), or Windows Defender blocked the execution before process creation completed. No network connection events (EID 3) are present, which would be expected for Active Directory enumeration against the specified domain controller (10.0.1.14). File creation events for the cache output file (`c:\temp\cache.txt`) are also missing, indicating the tool likely failed to execute or complete successfully.

## Assessment

This dataset provides strong evidence of PowerShell-based tool execution attempts but represents a potentially blocked or failed execution rather than successful SOAPHound operation. The PowerShell telemetry is excellent for detecting the attempt, with clear command lines and script block logging. However, the lack of SOAPHound process creation, network activity, or output file creation limits its utility for understanding the complete attack lifecycle. For detection engineering, this represents the important scenario where endpoint protection disrupts an attack but still generates valuable attempt indicators.

## Detection Opportunities Present in This Data

1. PowerShell command line containing "SOAPHound.exe" with Active Directory targeting parameters (--dc, --user, --buildcache flags)
2. PowerShell script block execution of external .exe files from AtomicRedTeam directory paths
3. Process creation with command lines containing hardcoded credentials (--password parameter)
4. PowerShell spawning child processes with suspicious reconnaissance tool patterns
5. Multiple PowerShell processes with .NET runtime loading in rapid succession indicating script execution
6. Process access events showing PowerShell accessing other processes with full access rights (0x1FFFFF)
7. PowerShell execution from SYSTEM context with domain controller IP addresses in command parameters
8. File creation in PowerShell profile directories indicating persistent execution preparation
9. Combination of whoami.exe execution with PowerShell-based tool deployment indicating reconnaissance workflow
