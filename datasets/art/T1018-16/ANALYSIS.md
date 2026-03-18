# T1018-16: Remote System Discovery — Remote System Discovery - Enumerate domain computers within Active Directory using DirectorySearcher

## Technique Context

T1018 Remote System Discovery involves adversaries attempting to get a listing of systems within the network for lateral movement planning. This specific test (T1018-16) demonstrates using the .NET DirectorySearcher class to query Active Directory for computer objects—a common technique used by both attackers and legitimate tools for domain enumeration.

DirectorySearcher is particularly valuable to attackers because it provides a native .NET API for LDAP queries against Active Directory without requiring external tools. The technique uses the LDAP filter `(ObjectCategory=Computer)` to enumerate all computer objects in the domain, making it effective for discovering potential lateral movement targets. Detection engineers focus on monitoring for DirectorySearcher instantiation, LDAP queries with computer-focused filters, and the resulting network traffic to domain controllers.

## What This Dataset Contains

This dataset captures a complete execution of PowerShell-based Active Directory computer enumeration:

**Primary PowerShell execution** in Security 4688 events shows the full command line: `"powershell.exe" & {$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher("(ObjectCategory=Computer)") $DirectorySearcher.PropertiesToLoad.Add("Name") $Computers = $DirectorySearcher.findall() foreach ($Computer in $Computers) { $Computer = $Computer.Properties.name if (!$Computer) { Continue } Write-Host $Computer}}`

**PowerShell script block logging** in EID 4104 captures the full technique implementation showing DirectorySearcher instantiation with the computer filter, property loading configuration, and result enumeration logic.

**PowerShell command invocation logging** in EID 4103 shows `New-Object` being called with `System.DirectoryServices.DirectorySearcher` as the TypeName and `(ObjectCategory=Computer)` as the ArgumentList, plus multiple `Write-Host` invocations displaying the discovered computer objects.

**Sysmon process creation** in EID 1 captures both the parent PowerShell process and a child PowerShell process executing the DirectorySearcher script, along with a `whoami.exe` execution.

**Network activity** appears in Sysmon DNS query (EID 22) showing resolution of `ACME-DC01.acme.local`, indicating communication with the domain controller for the LDAP query.

**Process access events** in Sysmon EID 10 show the PowerShell processes accessing each other and the whoami process, typical of the parent-child process relationship during script execution.

## What This Dataset Does Not Contain

The dataset lacks **direct LDAP network traffic** to the domain controller beyond the DNS resolution—the actual LDAP query packets are not visible in these event sources. **Specific computer names enumerated** are not explicitly logged in the captured events, though the PowerShell logs show `Write-Host` was called multiple times suggesting successful enumeration. **Directory Services audit events** (Security 5136-5139) that would show the actual directory queries are not present, likely because directory services auditing is not enabled in the test environment.

The dataset also doesn't contain **Windows Event Log service events** or **LDAP client logs** that might provide additional context about the directory queries being performed.

## Assessment

This dataset provides excellent telemetry for detecting DirectorySearcher-based domain enumeration. The combination of Security 4688 with full command lines, PowerShell script block logging, and PowerShell command invocation logs creates multiple detection opportunities at different levels of granularity.

The process creation events with complete command lines offer the most reliable detection points, while PowerShell logging provides detailed visibility into the .NET API calls and LDAP filter usage. The DNS resolution to the domain controller adds network-level context. However, the lack of directory services audit logs or LDAP traffic details limits deeper forensic analysis of exactly what data was retrieved.

For production detection engineering, this telemetry stack (especially the PowerShell logging) would be sufficient to reliably detect this technique variant.

## Detection Opportunities Present in This Data

1. **DirectorySearcher instantiation detection** - Monitor PowerShell 4103 events for `New-Object` calls with TypeName `System.DirectoryServices.DirectorySearcher` and computer-related LDAP filters

2. **LDAP computer enumeration filter detection** - Alert on PowerShell script blocks (4104) or command lines (4688) containing `ObjectCategory=Computer` or similar computer-focused LDAP queries  

3. **PowerShell domain enumeration pattern** - Correlate DirectorySearcher usage with `.findall()` method calls and property enumeration loops in PowerShell script blocks

4. **Suspicious domain controller DNS resolution** - Monitor DNS queries (Sysmon 22) for domain controller hostnames immediately followed by PowerShell DirectorySearcher activity

5. **Process ancestry analysis** - Track PowerShell processes creating child PowerShell processes with DirectorySearcher command lines, especially when combined with system user execution contexts

6. **Multiple Write-Host invocation correlation** - Detect sequences of PowerShell Write-Host commands (4103 events) with `System.DirectoryServices.ResultPropertyValueCollection` objects indicating enumerated results

7. **PowerShell execution policy bypass detection** - Monitor for `Set-ExecutionPolicy Bypass` in PowerShell 4103 events immediately before DirectorySearcher usage, indicating potential evasion attempts
