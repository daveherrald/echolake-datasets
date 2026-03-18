# T1069.002-10: Domain Groups — Enumerate Active Directory Groups with ADSISearcher

## Technique Context

T1069.002 (Domain Groups) is a Discovery technique where adversaries enumerate domain and local groups to understand the permissions and structure of the target environment. The ADSISearcher method is particularly common in PowerShell-based attacks, allowing threat actors to query Active Directory using LDAP filters without requiring specialized tools. This technique is frequently observed in post-exploitation phases where attackers map out domain group memberships to identify high-privilege targets, understand organizational structure, and plan lateral movement paths. Detection engineers focus on PowerShell activity involving ADSI objects, LDAP queries with "objectcategory=group" filters, and unusual process access patterns during AD enumeration.

## What This Dataset Contains

This dataset captures a PowerShell-based Active Directory group enumeration using the ADSISearcher .NET class. The core evidence appears in Security event 4688, showing the key command line: `"powershell.exe" & {([adsisearcher]"objectcategory=group").FindAll(); ([adsisearcher]"objectcategory=group").FindOne()}`. This command creates two ADSISearcher objects with LDAP filters targeting domain groups - one calling FindAll() to retrieve all matching groups, and another calling FindOne() to retrieve the first match.

The PowerShell telemetry includes script block logging (EID 4104) capturing the actual technique execution: `{([adsisearcher]"objectcategory=group").FindAll(); ([adsisearcher]"objectcategory=group").FindOne()}`. The dataset shows a clear process hierarchy with multiple PowerShell processes spawned during execution (PIDs 10096, 9196, 9088).

Sysmon provides rich context with process creation events showing PowerShell spawning (EID 1), .NET runtime loading events (EID 7) for System.Management.Automation.ni.dll, and process access events (EID 10) showing cross-process interactions during the enumeration. A DNS query event (EID 22) shows resolution of `ACME-DC01.acme.local`, indicating the workstation contacted the domain controller during the AD query operation. File creation events (EID 11) show PowerShell profile loading and schema cache access at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\acme.local.sch`.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry showing the actual LDAP traffic to the domain controller, despite the DNS resolution being captured. The technique completed successfully with no Windows Defender blocking (no STATUS_ACCESS_DENIED exit codes), indicating the enumeration was not flagged as malicious by the endpoint protection. 

The PowerShell channel primarily contains framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than detailed module loading or parameter binding for the ADSI operations. There are no Sysmon ProcessCreate events for the initial PowerShell processes due to the sysmon-modular include-mode filtering, though Security 4688 events provide complete coverage. Registry access events during AD operations are not captured, and there's no indication of the actual group data retrieved from the enumeration.

## Assessment

This dataset provides excellent coverage for detecting ADSISearcher-based domain group enumeration. The combination of Security 4688 command-line logging and PowerShell script block logging (4104) captures the exact technique syntax clearly. The DNS resolution to the domain controller adds valuable network context, while Sysmon process access and .NET runtime loading events provide behavioral indicators. The telemetry quality is high for building both signature-based and behavioral detections, though network-level LDAP monitoring would strengthen the dataset for comprehensive coverage of this common reconnaissance technique.

## Detection Opportunities Present in This Data

1. **Command Line Pattern Matching** - Security 4688 events containing "[adsisearcher]" combined with "objectcategory=group" indicate domain group enumeration attempts

2. **PowerShell Script Block Analysis** - PowerShell 4104 events with ADSISearcher instantiation and FindAll()/FindOne() method calls on group object categories

3. **Process Hierarchy Correlation** - Multiple PowerShell child processes spawned in sequence during AD enumeration operations, visible in Sysmon EID 1 and Security 4688

4. **DNS Resolution Correlation** - Sysmon EID 22 showing queries to domain controllers (*.domain.local patterns) temporally correlated with PowerShell ADSI activity

5. **Schema Cache File Access** - Sysmon EID 11 file creation events for Active Directory schema cache files (acme.local.sch) indicating AD query operations

6. **Cross-Process Access Patterns** - Sysmon EID 10 showing PowerShell processes accessing other PowerShell processes with high privileges (0x1FFFFF) during enumeration

7. **.NET Runtime Loading Sequence** - Sysmon EID 7 showing System.Management.Automation.ni.dll loading in PowerShell processes executing AD queries
