# T1016-6: System Network Configuration Discovery — Adfind - Enumerate Active Directory Subnet Objects

## Technique Context

T1016 System Network Configuration Discovery involves adversaries gathering information about network configuration and settings. This specific test (T1016-6) focuses on using AdFind.exe to enumerate Active Directory subnet objects, which provides attackers with valuable network topology intelligence. AdFind is a legitimate third-party Active Directory query tool frequently abused by threat actors for reconnaissance activities, including ransomware operators who use it to map domain infrastructure before lateral movement. The detection community focuses heavily on AdFind usage patterns, especially when executed with LDAP queries targeting network-related objects like subnets, sites, and domain controllers.

## What This Dataset Contains

This dataset captures a PowerShell-initiated execution of AdFind.exe with network discovery parameters. The key evidence appears in Security event 4688 showing cmd.exe spawning with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f (objectcategory=subnet)`. The Sysmon data provides complementary process creation events, with EID 1 capturing both the whoami.exe execution (`"C:\Windows\system32\whoami.exe"`) and the cmd.exe spawn (`"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f (objectcategory=subnet)`).

Notable process relationships show powershell.exe (PID 7360) as the parent for both whoami.exe (PID 2564) and cmd.exe (PID 5276). Sysmon EID 10 (Process Access) events capture PowerShell accessing both child processes with full access rights (0x1FFFFF), indicating normal parent-child process monitoring behavior. The Security channel captures process termination events (4689) for all spawned processes, with cmd.exe exiting with status 0x1, suggesting the AdFind execution may have encountered an error or access issue.

## What This Dataset Does Not Contain

The dataset lacks the actual AdFind.exe process creation event in Sysmon, which suggests either the sysmon-modular configuration doesn't include AdFind.exe in its process creation filters, or Windows Defender blocked the AdFind execution before it could complete. The cmd.exe exit status of 0x1 in Security event 4689 supports the latter theory. Crucially missing are any Sysmon network events (EID 3) that would typically accompany successful LDAP queries to domain controllers, and no DNS queries (EID 22) for domain controller resolution. The PowerShell events contain only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without any technique-specific script content.

## Assessment

This dataset provides limited utility for detection engineering focused on successful AdFind network discovery activities. While it captures the execution attempt with clear command-line evidence in both Security 4688 and Sysmon EID 1 events, the apparent blocking of the actual AdFind process significantly reduces the dataset's value for understanding the complete attack pattern. The data is most useful for detection of AdFind execution attempts rather than successful network reconnaissance. For stronger detection development, datasets would need successful AdFind executions that generate LDAP network traffic, DNS queries, and potential output file creation.

## Detection Opportunities Present in This Data

1. **AdFind Command Line Detection** - Security 4688 and Sysmon EID 1 events containing "AdFind.exe" with LDAP query parameters like "-f (objectcategory=subnet)"

2. **PowerShell-to-AdFind Process Chain** - Parent-child relationship between powershell.exe and cmd.exe executing AdFind with discovery parameters

3. **AdFind Path-Based Detection** - Process creation events referencing AdFind.exe from non-standard locations like "ExternalPayloads" directories

4. **Network Discovery Command Pattern** - Command lines containing both "AdFind.exe" and objectcategory filters targeting network objects (subnet, site, configuration)

5. **Process Access Pattern** - Sysmon EID 10 showing PowerShell accessing cmd.exe processes with full rights in conjunction with AdFind execution attempts

6. **Execution Error Correlation** - Cmd.exe exit status 0x1 combined with AdFind command lines indicating potential security control interference with reconnaissance tools
