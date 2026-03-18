# T1087.002-14: Domain Account — Enumerate Root Domain linked policies Discovery

## Technique Context

T1087.002 (Domain Account) involves adversaries enumerating domain accounts to understand the domain structure, identify privileged accounts, and map potential attack paths. This specific Atomic Red Team test focuses on enumerating Group Policy Objects (GPOs) linked to the root domain, which reveals critical information about domain security policies, administrative boundaries, and potential privilege escalation opportunities. Attackers use this information to understand domain administration patterns, identify high-value targets, and plan lateral movement or privilege escalation attacks. The detection community focuses on monitoring LDAP queries, PowerShell cmdlets accessing Active Directory objects, and unusual enumeration patterns that deviate from normal administrative activities.

## What This Dataset Contains

This dataset captures a PowerShell-based domain enumeration technique that queries Group Policy links from the domain root. The core activity is visible in Security event 4688 showing the PowerShell process creation with the command line: `"powershell.exe" & {(([adsisearcher]'').SearchRooT).Path | %{if(([ADSI]"$_").gPlink){Write-Host "[+] Domain Path:"([ADSI]"$_").Path;$a=((([ADSI]"$_").gplink) -replace "[[;]" -split "]");for($i=0;$i -lt $a.length;$i++){if($a[$i]){Write-Host "Policy Path[$i]:"([ADSI]($a[$i]).Substring(0,$a[$i].length-1)).Path;Write-Host "Policy Name[$i]:"([ADSI]($a[$i]).Substring(0,$a[$i].length-1)).DisplayName} };Write-Output "`n" }}}`.

The PowerShell execution trace shows successful domain queries through PowerShell events 4103 and 4104. Event 4103 captures cmdlet invocations including `Write-Host` calls showing the enumerated results: "[+] Domain Path:, LDAP://DC=acme,DC=local", "Policy Path[0]:, LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=acme,DC=local", and "Policy Name[0]:, System.DirectoryServices.PropertyValueCollection". Event 4104 shows the complete PowerShell script block containing the ADSI searcher and Group Policy enumeration logic.

Sysmon captures the process execution chain with events 1 showing PowerShell spawning (`powershell.exe`) and a `whoami.exe` process for system identification. Multiple Sysmon events 7 show .NET Framework and PowerShell module loading, indicating the execution environment setup. Event 11 captures file creation including AD schema cache updates (`acme.local.sch`) demonstrating Active Directory interaction artifacts.

## What This Dataset Does Not Contain

The dataset lacks detailed network-level telemetry showing the actual LDAP queries to domain controllers. While the PowerShell execution is well-documented, the underlying LDAP bind operations, search filters, and result sets are not captured in network logs. The Sysmon configuration's include-mode filtering for ProcessCreate likely missed some child processes or intermediate steps that weren't flagged as suspicious. Additionally, there are no Windows Security events related to directory service access (event IDs 4662-4665) that would normally accompany LDAP enumeration activities, suggesting either the audit policy doesn't cover directory service access or the queries didn't trigger these events under the execution context.

## Assessment

This dataset provides excellent visibility into PowerShell-based domain enumeration techniques through multiple complementary data sources. The Security channel captures the complete command line execution with full PowerShell syntax, while the PowerShell operational channel provides detailed script block logging and cmdlet invocation traces. Sysmon adds process genealogy and file system artifacts showing AD interaction evidence. The combination creates a comprehensive view of the technique execution from initial process creation through successful domain policy enumeration. The data quality is high for building behavioral detections focused on PowerShell-based ADSI queries and Group Policy enumeration patterns.

## Detection Opportunities Present in This Data

1. PowerShell command line detection for ADSI searcher patterns containing `([adsisearcher]'').SearchRoot` and `.gPlink` property access in Security event 4688

2. PowerShell script block analysis for Group Policy enumeration logic including `([ADSI]"$_").gplink` and policy path parsing in PowerShell event 4104

3. PowerShell cmdlet sequence analysis detecting Write-Host calls with LDAP DN patterns and "Policy Path" output formatting in PowerShell event 4103

4. Process ancestry detection for powershell.exe spawning secondary PowerShell instances with domain enumeration command lines in Sysmon event 1

5. File creation monitoring for Active Directory schema cache files (`*.sch`) indicating domain interaction in Sysmon event 11

6. PowerShell module loading correlation with System.Management.Automation and .NET Framework components during enumeration activities in Sysmon event 7

7. Behavioral detection combining PowerShell execution with AD-related file artifacts and domain controller communication patterns

8. Command line obfuscation detection for escaped quotes and PowerShell invoke patterns targeting ADSI objects
