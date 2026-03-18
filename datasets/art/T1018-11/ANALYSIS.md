# T1018-11: Remote System Discovery — Adfind - Enumerate Active Directory Domain Controller Objects

## Technique Context

T1018 Remote System Discovery involves adversaries attempting to identify remote systems within their environment, often as part of network reconnaissance. AdFind is a commonly abused legitimate command-line tool for querying Active Directory that threat actors frequently use to enumerate domain controllers, users, groups, and other AD objects. The detection community focuses heavily on AdFind usage patterns, particularly the `-sc dclist` parameter which specifically enumerates domain controllers - a high-value target for attackers planning lateral movement or privilege escalation. This technique is often observed in APT campaigns and ransomware operations where attackers need to map the domain infrastructure before proceeding with their objectives.

## What This Dataset Contains

The dataset captures a PowerShell-initiated execution of AdFind with domain controller enumeration parameters. The key evidence appears in Security event 4688 showing the command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -sc dclist`. The process chain shows powershell.exe (PID 6444) spawning cmd.exe (PID 7868) which was intended to execute AdFind. However, the cmd.exe process exits with status 0x1 (failure), and crucially, there is no Sysmon ProcessCreate event for AdFind.exe itself, indicating the tool was not successfully executed. Sysmon captures the cmd.exe creation (EID 1) with the full AdFind command line, process access events (EID 10) showing PowerShell accessing the cmd.exe process, and various PowerShell .NET assembly loading events (EID 7). The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific PowerShell commands.

## What This Dataset Does Not Contain

The dataset is missing the actual AdFind.exe execution - there are no ProcessCreate, network connections, or file access events from AdFind itself. The cmd.exe exit status of 0x1 suggests AdFind either failed to launch or was blocked, likely by Windows Defender which was active with real-time protection enabled. There are no network events showing LDAP queries to domain controllers, no DNS queries for domain controller discovery, and no file operations that would indicate successful AD enumeration results being written to disk. The absence of these artifacts means the technique was attempted but not successfully executed.

## Assessment

This dataset provides limited utility for detection engineering focused on successful AdFind operations, as the tool itself never executed. However, it offers valuable insight into blocked technique attempts and demonstrates how endpoint protection can prevent technique completion while still generating detectable process creation telemetry. The Security 4688 events with command-line logging provide the strongest detection opportunity, clearly showing the AdFind invocation attempt with the suspicious `-sc dclist` parameter. For building detections around AdFind usage patterns, this dataset would need to be supplemented with examples where the tool successfully executes and generates network traffic or file artifacts.

## Detection Opportunities Present in This Data

1. **AdFind Command Line Detection** - Security EID 4688 captures the full command line `"C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -sc dclist` which contains both the tool path and the domain controller enumeration parameter

2. **AdFind Tool Path Detection** - The ExternalPayloads directory path combined with AdFind.exe provides a specific indicator of this common red team tool

3. **PowerShell to CMD Chain with External Tool** - The process chain powershell.exe → cmd.exe with `/c` parameter executing a non-standard executable path from ExternalPayloads directory

4. **Failed Process Execution Correlation** - CMD.exe exit status 0x1 combined with missing child process creation can indicate blocked tool execution attempts

5. **Suspicious Tool Parameter Detection** - The `-sc dclist` parameter is a specific indicator of domain controller enumeration activity that rarely appears in legitimate administrative scripts
