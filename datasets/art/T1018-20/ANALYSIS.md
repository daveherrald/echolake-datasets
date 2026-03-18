# T1018-20: Remote System Discovery — Get-WmiObject to Enumerate Domain Controllers

## Technique Context

T1018 Remote System Discovery involves adversaries attempting to identify systems on the network that they can access or may be valuable for lateral movement. This specific test focuses on using PowerShell's `Get-WmiObject` cmdlet to query Active Directory through WMI's LDAP provider to enumerate domain controllers. Attackers frequently use this technique during the reconnaissance phase to map out domain infrastructure and identify high-value targets like domain controllers.

The detection community focuses heavily on WMI-based domain enumeration because it's a common post-compromise activity that generates distinctive telemetry patterns. Key indicators include PowerShell processes executing WMI queries against the `root\directory\ldap` namespace, DNS queries to domain controllers, and specific WMI provider activity.

## What This Dataset Contains

This dataset captures a successful execution of `Get-WmiObject -class ds_computer -namespace root\directory\ldap` to enumerate domain computers. The evidence includes:

**Process Creation Evidence:**
- Security EID 4688 shows PowerShell process creation with command line: `"powershell.exe" & {try { get-wmiobject -class ds_computer -namespace root\directory\ldap -ErrorAction Stop } catch { $_; exit $_.Exception.HResult }}`
- Sysmon EID 1 captures the same PowerShell process with additional metadata and file hashes

**PowerShell Activity:**
- PowerShell EID 4103 shows the actual `Get-WmiObject` command invocation with parameters: `Class="ds_computer"`, `Namespace="root\directory\ldap"`, `ErrorAction="Stop"`
- PowerShell EID 4104 script blocks contain the complete command execution context

**WMI Infrastructure Activity:**
- Sysmon EID 7 shows `wmiutils.dll` loading into PowerShell (rule: `technique_id=T1047,technique_name=Windows Management Instrumentation`)
- Sysmon EID 22 DNS query from `wmiprvse.exe` to `ACME-DC01.acme.local` (192.168.4.10)
- Sysmon EID 11 shows WMI provider creating schema cache file: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\acme.local.sch`

## What This Dataset Does Not Contain

The dataset doesn't include the actual results of the WMI query - we can see the command executed successfully (exit code 0x0) but don't have visibility into what domain computers were returned. There are no WMI-specific event logs (Microsoft-Windows-WMI-Activity channel) that would show the detailed WMI operation results. The technique appears to have completed successfully without Windows Defender intervention, as evidenced by the clean process exits and lack of access denied errors.

## Assessment

This dataset provides excellent coverage for detecting WMI-based domain enumeration. The combination of command-line logging, PowerShell script block logging, and Sysmon telemetry creates multiple overlapping detection opportunities. The DNS query to the domain controller and WMI infrastructure activity provide strong contextual indicators that distinguish this from benign PowerShell/WMI usage. The presence of both high-fidelity (PowerShell cmdlet invocation) and behavioral (DNS queries, DLL loading patterns) indicators makes this dataset particularly valuable for building robust detection rules.

## Detection Opportunities Present in This Data

1. **PowerShell WMI LDAP Query**: Detect `Get-WmiObject` with `-namespace root\directory\ldap` parameter combinations in PowerShell EID 4103 CommandInvocation events

2. **Process Command Line Pattern**: Alert on command lines containing `get-wmiobject`, `-class ds_computer`, and `root\directory\ldap` in Security EID 4688 or Sysmon EID 1

3. **WMI DLL Loading**: Monitor Sysmon EID 7 for `wmiutils.dll` loading into PowerShell processes, especially when combined with LDAP namespace queries

4. **WMI Provider DNS Activity**: Correlate Sysmon EID 22 DNS queries from `wmiprvse.exe` to domain controllers with concurrent PowerShell WMI activity

5. **Schema Cache File Creation**: Track Sysmon EID 11 file creation events for `*.sch` files in the SchCache directory as indicators of Active Directory WMI queries

6. **PowerShell Script Block Content**: Parse PowerShell EID 4104 script blocks for `ds_computer` class references combined with LDAP namespace specifications
