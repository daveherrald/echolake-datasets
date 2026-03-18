# T1087.002-4: Domain Account — Automated AD Recon (ADRecon)

## Technique Context

T1087.002 Domain Account is a Discovery technique where adversaries enumerate domain accounts to understand the environment and identify high-value targets. This differs from local account discovery by focusing on Active Directory objects that provide insights into organizational structure, privileged accounts, and potential lateral movement paths. The detection community primarily focuses on identifying automated enumeration tools, unusual query patterns, and privileged account access from non-administrative contexts.

ADRecon is a widely-used PowerShell-based Active Directory reconnaissance tool that performs comprehensive enumeration of domain objects, including users, groups, computers, GPOs, and trust relationships. It's frequently employed by both penetration testers and threat actors for post-compromise domain mapping. The tool generates detailed reports that can reveal attack paths and privileged account relationships, making its detection a priority for defenders.

## What This Dataset Contains

This dataset captures the execution of ADRecon via PowerShell script invocation. The core evidence appears in Security event 4688, which shows PowerShell spawning with the command line `"powershell.exe" & {Invoke-Expression \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\ADRecon.ps1\"}`. Sysmon event 1 provides the corresponding process creation with additional metadata including parent process details and file hashes.

The PowerShell channel contains minimal technique-specific content beyond the standard execution policy bypass (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`) and the script invocation command (`& {Invoke-Expression "C:\AtomicRedTeam\atomics\..\ExternalPayloads\ADRecon.ps1"}`). Most script block events are PowerShell test framework boilerplate.

Sysmon captures typical PowerShell process initialization telemetry including .NET CLR loading, PowerShell assembly loading, and Windows Defender integration DLLs. Process access events (EID 10) show PowerShell accessing both `whoami.exe` and a child PowerShell process, consistent with the tool's execution methodology.

## What This Dataset Does Not Contain

The dataset lacks the most valuable telemetry for detecting ADRecon execution. There are no LDAP query events that would show the actual Active Directory enumeration activities - the core malicious behavior of this technique. The absence of Security events 4624 (logon), 4768/4769 (Kerberos authentication), or 4648 (explicit credential use) suggests no authentication events were captured during domain queries.

Critically missing are any Security events in the 5136-5139 range (directory service access) that would indicate Active Directory object enumeration. Network connection events that would show LDAP traffic to domain controllers are also absent from this dataset. The lack of file creation events for ADRecon's typical output reports (CSV/HTML files) indicates either the tool failed to execute completely or the output was not captured in this timeframe.

## Assessment

This dataset has limited utility for building detection rules specifically for ADRecon or domain account enumeration techniques. While it captures the initial PowerShell execution vector, it completely misses the substantive Active Directory reconnaissance activities that define this technique. The telemetry is more valuable for detecting PowerShell-based tool deployment rather than the domain enumeration behavior itself.

The process creation and command line logging provide basic visibility for signature-based detection of ADRecon by name, but sophisticated attackers would easily evade such rules through renaming or encoding. For comprehensive T1087.002 detection, analysts would need access to domain controller logs, LDAP query monitoring, or specialized Active Directory auditing tools that this dataset doesn't include.

## Detection Opportunities Present in This Data

1. **PowerShell script execution with external payload paths** - Security 4688 command line contains `C:\AtomicRedTeam\atomics\..\ExternalPayloads\ADRecon.ps1` indicating execution from a known testing framework location

2. **Invoke-Expression with external script files** - PowerShell script blocks show `Invoke-Expression` being used to execute scripts from disk, a common pattern for loading reconnaissance tools

3. **PowerShell process spawning child PowerShell processes** - Sysmon process tree shows PowerShell (PID 18264) spawning another PowerShell instance (PID 20948) which can indicate tool deployment patterns

4. **Execution policy bypass in automated contexts** - Multiple PowerShell instances rapidly executing `Set-ExecutionPolicy Bypass` suggests scripted execution rather than interactive use

5. **Whoami.exe execution from PowerShell** - Sysmon EID 1 captures `whoami.exe` spawned from PowerShell, often used by reconnaissance tools for initial context gathering

6. **PowerShell loading System.Management.Automation** - Sysmon EID 7 shows loading of PowerShell automation assemblies that are required for advanced PowerShell-based tools
