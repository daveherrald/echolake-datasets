# T1087.002-16: Domain Account — Kerbrute - userenum

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries enumerating domain accounts to understand the environment and identify high-value targets. Kerbrute is a popular tool that leverages Kerberos pre-authentication to enumerate valid domain usernames without triggering account lockouts. Unlike traditional LDAP enumeration, Kerbrute sends AS-REQ requests to domain controllers, making it stealthier and less likely to generate security alerts. The detection community focuses on identifying unusual Kerberos authentication patterns, process execution of enumeration tools, and network traffic to domain controllers from workstations.

## What This Dataset Contains

This dataset captures the execution of Kerbrute's user enumeration functionality through PowerShell. The Security channel shows the PowerShell process creation with the full command line: `"powershell.exe" & {cd "C:\AtomicRedTeam\atomics\..\ExternalPayloads\"` followed by `.\kerbrute.exe userenum -d $env:USERDOMAIN --dc $env:UserDnsDomain "C:\AtomicRedTeam\atomics\..\ExternalPayloads\username.txt"}` (Security EID 4688). The PowerShell channel captures the script block execution showing the Kerbrute command being prepared and executed (EID 4104). Sysmon captures the PowerShell process creation (EID 1) with the same command line, along with typical PowerShell .NET runtime loading (EIDs 7) and pipe creation for the PowerShell host (EID 17). The process chain shows powershell.exe spawning another powershell.exe process to execute the Kerbrute command.

## What This Dataset Does Not Contain

Critically, this dataset does not contain the actual Kerbrute executable process creation or execution. The sysmon-modular configuration uses include-mode filtering for ProcessCreate events, and Kerbrute is not in the suspicious process patterns list, so EID 1 events for kerbrute.exe are filtered out. There are no network connection events (Sysmon EID 3) showing the Kerberos traffic to domain controllers that would be the primary indicator of this technique's success. No Kerberos-related Security events (4768, 4771, 4776) are present, which would typically show the AS-REQ attempts. The dataset lacks any indication of whether the enumeration was successful or what usernames were discovered.

## Assessment

This dataset provides limited utility for detecting the actual T1087.002 technique execution. While it captures the PowerShell wrapper that launches Kerbrute, the absence of the tool's process creation, network connections, and Kerberos authentication events significantly reduces its detection value. The PowerShell command line is clearly suspicious and would trigger alerts, but this represents the attack preparation rather than execution. For comprehensive Kerbrute detection, you would need Sysmon network events, domain controller logs, or a ProcessCreate configuration that captures all executables rather than filtered known-suspicious patterns.

## Detection Opportunities Present in This Data

1. **PowerShell command line analysis** - Security EID 4688 and Sysmon EID 1 show execution of kerbrute.exe with domain enumeration parameters (`userenum -d $env:USERDOMAIN --dc $env:UserDnsDomain`)

2. **PowerShell script block execution** - PowerShell EID 4104 captures the script block containing the Kerbrute execution command, enabling detection of the tool name and parameters

3. **Process ancestry analysis** - Sysmon EID 1 shows powershell.exe spawning another powershell.exe process with suspicious command line arguments for domain enumeration

4. **File path indicators** - Command lines reference suspicious paths like `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` and `kerbrute.exe`, indicating potential red team tool usage

5. **Domain enumeration parameters** - Detection of command line arguments specific to domain account enumeration (`userenum`, `-d`, `--dc`) combined with environment variables for domain targeting
