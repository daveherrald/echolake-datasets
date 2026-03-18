# T1069.002-2: Domain Groups — Permission Groups Discovery via PowerShell (Domain)

## Technique Context

T1069.002 (Domain Groups) with `Get-ADPrincipalGroupMembership` represents a targeted reconnaissance approach: rather than enumerating all groups, the attacker asks specifically which groups the current user belongs to. This is a natural first step after initial access — an attacker wants to know immediately whether the compromised account is a member of Domain Admins, IT Administrators, or any other privileged group that enables immediate escalation. The `$env:USERNAME` variable makes the query self-referential, meaning it adapts to whatever context the attacker is running in.

`Get-ADPrincipalGroupMembership` is a native Active Directory PowerShell module cmdlet, part of the RSAT (Remote Server Administration Tools) Active Directory module. Its use requires the AD module to be installed, which is standard on domain-joined workstations managed in enterprise environments. Because it is a legitimate administrative tool, it is often in SIEM allowlists, making it harder to detect on alert alone. Detection focuses on unusual execution context (running from scripting environments or non-admin user sessions), the specific cmdlet name in script block logs, and LDAP activity to domain controllers from workstations.

## What This Dataset Contains

The technique execution is visible in Security EID 4688, which captures the PowerShell command:

```
"powershell.exe" & {get-ADPrincipalGroupMembership $env:USERNAME | select name}
```

This queries the Active Directory module for all groups the current user is a member of, piping to `select name` to display only group names. Sysmon EID 1 confirms this process creation with the same command line, showing the execution was spawned by the ART test framework PowerShell process.

Sysmon provides 26 events across five types: 15 EID 7 (image load), 4 EID 1 (process create), 4 EID 10 (process access), 2 EID 17 (pipe create), and 1 EID 11 (file create). The named pipe events (EID 17) capture two pipes: `\PSHost.134180042017983358.5776.DefaultAppDomain.powershell` (the ART test framework host) and `\PSHost.134180042060558968.4508.DefaultAppDomain.powershell` (the child process executing the AD query). These pipe names encode the PowerShell process ID and domain, providing forensic process identity confirmation independent of process creation logging. The EID 7 image loads include `mpclient.dll` and `UrlMon.dll` loading into PowerShell — the UrlMon.dll load is notable as it indicates web request capabilities were initialized, though this test does not make external network requests. The file creation event (EID 11) reflects PowerShell profile or schema cache activity consistent with AD module initialization.

The PowerShell channel has 103 EID 4104 events, all ART test framework boilerplate in the sample set. The cleanup invocation is logged: `Invoke-AtomicTest T1069.002 -TestNumbers 2 -Cleanup -Confirm:$false`.

Compared to the defended version (46 sysmon, 10 security, 53 PowerShell events), this undefended run has slightly fewer sysmon events (26 vs 46 — notably lower), fewer security events (4 vs 10), and notably more PowerShell events (103 vs 53). The sysmon count difference is significant: the defended run generated many more sysmon events (46), suggesting Defender's active monitoring and intervention created additional process activity. The high undefended PS count (103) reflects the full AD module initialization and execution.

## What This Dataset Does Not Contain

The LDAP traffic to the domain controller is not captured in any network telemetry. `Get-ADPrincipalGroupMembership` performs LDAP queries to enumerate the group memberships, but no Sysmon EID 3 network connection events appear in the dataset. The enumeration results — the actual list of groups the current user belongs to — exist only in process memory and console output.

The sysmon sample does not include EID 22 DNS query events despite this cmdlet necessarily contacting the domain controller. These may have been filtered by Sysmon configuration or fell outside the sample window.

## Assessment

This is a clean, successful execution of a native AD cmdlet for user-centric group enumeration. The command line in EID 4688 is specific and detectable: `Get-ADPrincipalGroupMembership` is not commonly executed from non-administrative workflows. The PowerShell named pipe creation events provide supplementary process identity telemetry. The full execution (confirmed by 103 PS events vs 53 in defended run) means the dataset reflects what an attacker actually receives — group membership information for the compromised account.

This dataset is useful for validating detections on native AD cmdlet usage for group discovery, especially distinguishing between legitimate admin use and post-exploitation reconnaissance based on execution context.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `Get-ADPrincipalGroupMembership` in PowerShell command line**: The cmdlet name in a process command line is unambiguous. When executed from a non-admin workstation context, particularly from a scripting test framework (PowerShell spawning PowerShell), this is a strong indicator of automated reconnaissance.

2. **EID 4104 — script block containing `Get-ADPrincipalGroupMembership $env:USERNAME`**: Script block logging captures the self-referential `$env:USERNAME` pattern. An attacker querying their own group memberships immediately after access is temporally distinctive from routine admin activity.

3. **Sysmon EID 17 — named pipe creation from PowerShell**: Named pipes matching `\PSHost.*DefaultAppDomain.powershell` are created by PowerShell host processes. When multiple such pipes exist with overlapping timestamps from processes with suspicious command lines, they indicate coordinated PowerShell execution.

4. **UrlMon.dll load in PowerShell without subsequent network activity**: The `UrlMon.dll` image load (EID 7) in a PowerShell process that does not generate network connection events (EID 3) may indicate module initialization overhead or preparation for a download that was not executed in this run.

5. **AD module execution from workstation context**: `Get-ADPrincipalGroupMembership` requires the Active Directory module, which loads specific DLLs. Its execution from a standard workstation PowerShell session (rather than a DC or admin console) is anomalous in most environments and worth baseline monitoring.
