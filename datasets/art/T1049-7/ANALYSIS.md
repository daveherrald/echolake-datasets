# T1049-7: System Network Connections Discovery — System Discovery using SharpView

## Technique Context

T1049 System Network Connections Discovery is a reconnaissance technique where adversaries gather information about network connections and listening ports on compromised systems. This intelligence helps attackers understand network topology, identify additional targets, and discover services running on the host. The technique is commonly implemented through built-in utilities like `netstat`, `ss`, or third-party tools.

This specific test uses SharpView, a C# port of PowerView that provides Active Directory enumeration capabilities. While SharpView is primarily known for AD reconnaissance, this test attempts to execute three specific functions: `Invoke-ACLScanner`, `Invoke-Kerberoast`, and `Find-DomainShare`. The detection community typically focuses on process creation events, command-line arguments containing network enumeration tools, and the execution of reconnaissance frameworks like SharpView.

## What This Dataset Contains

The dataset captures a PowerShell-driven execution of SharpView with three specific reconnaissance functions. The key evidence includes:

- **Security 4688**: Process creation for `powershell.exe` with command line `"powershell.exe" & {$syntaxList = \"Invoke-ACLScanner\", \"Invoke-Kerberoast\", \"Find-DomainShare\" foreach ($syntax in $syntaxList) {C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpView.exe $syntax -}}`
- **PowerShell 4104**: Script block logging capturing the loop structure executing SharpView commands
- **Sysmon 1**: Process creation events for `whoami.exe` and nested PowerShell processes
- **Sysmon 7**: Multiple image loads including .NET runtime components and Windows Defender DLLs
- **Sysmon 10**: Process access events showing PowerShell accessing spawned processes
- **Sysmon 11**: File creation events for PowerShell startup profiles
- **Sysmon 17**: Named pipe creation for PowerShell host communication

Notably absent from the dataset are any Sysmon ProcessCreate (EID 1) events for SharpView.exe execution, despite the command line explicitly calling `C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpView.exe` with the three enumeration parameters.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence for this technique - the actual execution of SharpView.exe. There are no Sysmon EID 1 events showing SharpView process creation, no network connection events (Sysmon EID 3), and no DNS queries (Sysmon EID 22) that would typically accompany domain enumeration activities. This absence is likely due to Windows Defender blocking the SharpView execution or the sysmon-modular configuration not capturing the SharpView process creation since it may not match the include-mode filtering patterns.

The PowerShell script block logging captures the intended execution but provides no evidence that the SharpView commands actually ran successfully. Additionally, there are no Security 4688 events for SharpView.exe, suggesting the process never started or was immediately terminated.

## Assessment

This dataset has limited utility for detection engineering focused on T1049 System Network Connections Discovery. While it demonstrates the PowerShell wrapper attempting to execute SharpView reconnaissance functions, the absence of actual SharpView execution makes it more valuable for detecting attempted rather than successful reconnaissance activities. The telemetry is excellent for identifying PowerShell-based enumeration frameworks and command-line indicators but provides no insight into the network discovery behaviors that define T1049.

The data sources present (Security process auditing, PowerShell logging, Sysmon process/image monitoring) are appropriate for this technique, but the blocked execution significantly reduces the dataset's value for understanding successful technique implementation.

## Detection Opportunities Present in This Data

1. **PowerShell script block detection** - PowerShell EID 4104 events contain the complete SharpView execution loop with enumeration function names like "Invoke-ACLScanner", "Invoke-Kerberoast", and "Find-DomainShare"

2. **Command-line enumeration tool detection** - Security EID 4688 captures the full command line referencing SharpView.exe with reconnaissance parameters

3. **Reconnaissance framework path detection** - Command line contains the AtomicRedTeam ExternalPayloads directory structure commonly used for offensive tooling

4. **PowerShell process spawning patterns** - Multiple nested PowerShell processes with System-level execution indicating potential automation or testing frameworks

5. **Active Directory enumeration keyword detection** - Script blocks contain specific PowerView/SharpView function names associated with domain reconnaissance activities
