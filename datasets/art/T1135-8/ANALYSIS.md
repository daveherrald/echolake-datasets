# T1135-8: Network Share Discovery — PowerView ShareFinder

## Technique Context

T1135 Network Share Discovery involves adversaries attempting to enumerate network shares and shared drives on systems within the network. This technique is commonly used during the Discovery phase to identify accessible file shares that may contain sensitive data or provide lateral movement opportunities. PowerView's `Invoke-ShareFinder` function is a popular post-exploitation tool that automates the discovery of network shares across domain computers, making it a frequent choice for penetration testers and threat actors alike. The detection community focuses on monitoring for rapid enumeration of multiple network shares, SMB traffic patterns, and the execution of known share discovery tools like PowerView.

## What This Dataset Contains

This dataset captures the execution of PowerView's `Invoke-ShareFinder` with the `-CheckShareAccess` parameter. The Security channel shows the complete process chain: the parent PowerShell process (PID 38596) spawning a child PowerShell process (PID 41572) with the command line `"powershell.exe" & {Import-Module \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\PowerView.ps1\" Invoke-ShareFinder -CheckShareAccess}`. Sysmon captures rich telemetry including ProcessCreate events for both PowerShell processes and whoami.exe execution, multiple ImageLoad events showing .NET runtime loading and Windows Defender DLL injection, ProcessAccess events indicating inter-process communication, and PipeCreated events for PowerShell named pipes. The PowerShell channel contains the actual technique execution in script blocks showing `Import-Module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PowerView.ps1"` and `Invoke-ShareFinder -CheckShareAccess`, along with typical test framework boilerplate like `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.

## What This Dataset Does Not Contain

This dataset lacks the network-level telemetry that would typically accompany successful share discovery operations. There are no DNS queries to resolve target hostnames, no network connections (Sysmon EID 3) showing SMB traffic to remote systems, no file access events indicating successful share enumeration, and no registry queries that might occur during domain computer discovery. The execution appears to complete quickly without the extended runtime typically seen when PowerView successfully discovers and tests access to multiple network shares. This suggests the technique may have executed but found limited targets in the test environment, or Windows Defender may have interfered with some network operations despite not explicitly blocking the PowerShell execution.

## Assessment

This dataset provides good coverage of the initial execution phase of PowerView ShareFinder but lacks the network discovery telemetry that would make it highly valuable for detection engineering. The PowerShell script block logging captures the exact commands executed, and the process creation events show clear indicators of PowerView usage. However, the absence of network connections and SMB traffic significantly limits its utility for building detections focused on the actual share discovery behavior. The dataset would be stronger with Sysmon network connection events, DNS queries, and evidence of successful share enumeration attempts.

## Detection Opportunities Present in This Data

1. **PowerView Module Import Detection** - Monitor PowerShell script block logs (EID 4104) for `Import-Module` commands referencing PowerView.ps1 or similar offensive security tools
2. **ShareFinder Function Execution** - Detect PowerShell script blocks containing `Invoke-ShareFinder` function calls, particularly with parameters like `-CheckShareAccess`
3. **Suspicious PowerShell Command Line Patterns** - Alert on process creation (Security EID 4688, Sysmon EID 1) with command lines containing embedded PowerShell scripts that import external modules from suspicious paths
4. **PowerShell Child Process Spawning** - Monitor for PowerShell processes spawning additional PowerShell processes with complex command lines, which may indicate script execution frameworks
5. **Execution Policy Bypass Detection** - Track PowerShell module logging (EID 4103) for `Set-ExecutionPolicy` commands with `Bypass` parameter, especially when combined with other suspicious activities
6. **Named Pipe Creation by PowerShell** - Monitor Sysmon EID 17 for PowerShell processes creating named pipes with patterns like `\PSHost.*powershell`, which may indicate script execution
7. **Process Access from PowerShell** - Detect Sysmon EID 10 events showing PowerShell processes accessing other processes with high privileges (0x1FFFFF), potentially indicating injection or monitoring activities
