# T1087.002-13: Domain Account — Enumerate Linked Policies In ADSISearcher Discovery

## Technique Context

T1087.002 (Domain Account) represents adversary attempts to enumerate domain accounts and objects within an Active Directory environment. This specific test demonstrates a sophisticated PowerShell-based enumeration technique that discovers organizational units (OUs) and their linked Group Policy Objects (GPOs) using Active Directory Service Interfaces (ADSI). Attackers use this technique during reconnaissance phases to understand domain structure, policy inheritance, and potential privilege escalation paths.

The detection community focuses on LDAP queries, PowerShell command patterns involving ADSI objects, and suspicious domain enumeration activity. This technique is particularly valuable to attackers because it reveals the organizational structure and policy enforcement mechanisms that could be exploited for lateral movement or privilege escalation.

## What This Dataset Contains

This dataset captures a PowerShell-based ADSI enumeration attack that successfully executes and produces domain intelligence. The core technique appears in PowerShell event 4104 as a complex one-liner:

```powershell
& {(([adsisearcher]'(objectcategory=organizationalunit)').FindAll()).Path | %{if(([ADSI]"$_").gPlink){Write-Host "[+] OU Path:"([ADSI]"$_").Path;$a=((([ADSI]"$_").gplink) -replace "[[;]" -split "]");for($i=0;$i -lt $a.length;$i++){if($a[$i]){Write-Host "Policy Path[$i]:"([ADSI]($a[$i]).Substring(0,$a[$i].length-1)).Path;Write-Host "Policy Name[$i]:"([ADSI]($a[$i]).Substring(0,$a[$i].length-1)).DisplayName} };Write-Output "`n" }}}
```

Security event 4688 captures the PowerShell process creation with the full command line, showing the technique executed as a child process. PowerShell events 4103 reveal successful execution with specific Write-Host commands displaying discovered information: "OU Path: LDAP://OU=Domain Controllers,DC=acme,DC=local" and "Policy Path[0]: LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=acme,DC=local".

Sysmon captures the process creation chain (EID 1) showing powershell.exe spawning another powershell.exe instance, and file creation events (EID 11) indicating Active Directory schema cache access at "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\acme.local.sch".

## What This Dataset Does Not Contain

The dataset lacks network-level LDAP query telemetry that would show the actual directory service communications. While we see the PowerShell command and successful output, there are no DNS queries or network connections captured in Sysmon that would typically accompany ADSI queries. The technique completed successfully without triggering any Windows Defender detections or access denied errors, indicating the enumeration was unimpeded.

Missing are detailed LDAP bind events or directory service audit logs (event IDs 4662, 4624) that would provide visibility into the actual directory queries being performed. The sysmon-modular configuration may have filtered some network events that could have provided additional context about the LDAP communications.

## Assessment

This dataset provides excellent visibility into PowerShell-based domain enumeration techniques from both process creation and script execution perspectives. The combination of Security 4688 with full command-line logging and PowerShell 4103/4104 events creates multiple detection opportunities for this sophisticated ADSI-based enumeration. The successful execution and output capture make this particularly valuable for understanding how attackers extract domain policy information.

The dataset would be stronger with network-level telemetry showing LDAP queries and responses, but the PowerShell telemetry is comprehensive and provides clear indicators of malicious domain reconnaissance activity.

## Detection Opportunities Present in This Data

1. **PowerShell ADSI Enumeration Pattern**: Monitor PowerShell 4104 events for scripts containing `[adsisearcher]` with `objectcategory=organizationalunit` queries combined with `.FindAll()` methods.

2. **GPLink Policy Enumeration**: Detect PowerShell commands accessing `.gPlink` properties of ADSI objects, particularly when combined with string manipulation operations using `-replace` and `-split`.

3. **Suspicious PowerShell Command Line**: Alert on Security 4688 events with command lines containing encoded or complex PowerShell invoking ADSI searcher objects for organizational unit enumeration.

4. **Active Directory Schema Cache Access**: Monitor Sysmon 11 events for file creation in SchCache directories (*.sch files) correlating with PowerShell processes performing domain queries.

5. **PowerShell Execution Chain Analysis**: Detect PowerShell processes spawning child PowerShell processes (parent-child relationship in Sysmon 1) with domain enumeration command arguments.

6. **ADSI Object Property Access Pattern**: Monitor PowerShell 4103 CommandInvocation events for Write-Host commands displaying LDAP paths, particularly those revealing organizational unit and policy structures.
