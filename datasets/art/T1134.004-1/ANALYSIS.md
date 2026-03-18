# T1134.004-1: Parent PID Spoofing — Parent PID Spoofing using PowerShell

## Technique Context

Parent PID Spoofing (T1134.004) is a defense evasion and privilege escalation technique where attackers modify the parent process identifier of a newly created process to disguise its true lineage. This breaks the normal process tree hierarchy, making it appear that a process was spawned by a different (often trusted) parent process. Attackers commonly use this technique to evade process monitoring solutions that rely on parent-child relationships for detection logic, or to inherit privileges from a spoofed parent process.

The detection community focuses on several key indicators: unusual process creation patterns that break expected parent-child relationships, processes created with unexpected privileges for their apparent parent, and direct API calls to CreateProcess with modified STARTUPINFOEX structures containing spoofed parent PIDs. This technique is particularly concerning because it can bypass security tools that whitelist processes based on their apparent lineage.

## What This Dataset Contains

This dataset captures a PowerShell-based parent PID spoofing implementation using the PPID-Spoof.ps1 script from Atomic Red Team. The execution begins with Security event 4688 showing PowerShell launching with the command line containing the full spoofing script: `"powershell.exe" & {. "C:\AtomicRedTeam\atomics\T1134.004\src\PPID-Spoof.ps1" $ppid=Get-Process explorer | select -expand id PPID-Spoof -ppid $ppid -spawnto "C:\Program Files\Internet Explorer\iexplore.exe" -dllpath "C:\AtomicRedTeam\atomics\T1134.004\bin\calc.dll"}`.

The key evidence includes PowerShell scriptblock logging (event 4104) capturing the script execution: `& {. "C:\AtomicRedTeam\atomics\T1134.004\src\PPID-Spoof.ps1"`. Security event 4703 shows privilege adjustments with multiple high-value privileges enabled including SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege, which are necessary for process creation manipulation.

Sysmon captures extensive process access events (EID 10) showing PowerShell processes accessing other processes with GrantedAccess 0x1FFFFF (full access), including accesses to whoami.exe and another PowerShell instance. The CallTrace data reveals the technique in action, showing calls through System.Management.Automation.ni.dll indicating PowerShell's process manipulation capabilities.

Process creation events show the normal PowerShell parent-child relationships that the technique is designed to subvert, with Sysmon EID 1 events capturing whoami.exe and the target PowerShell process being created as expected children of the original PowerShell process.

## What This Dataset Does Not Contain

Critically, this dataset does not contain evidence of the actual parent PID spoofing success. While we see the script execution and privilege adjustments, there are no Sysmon process creation events showing Internet Explorer (iexplore.exe) being created with a spoofed parent PID of the explorer process. The target executable path `"C:\Program Files\Internet Explorer\iexplore.exe"` referenced in the command line does not appear in any process creation events.

The dataset also lacks file creation events for the referenced calc.dll payload at `"C:\AtomicRedTeam\atomics\T1134.004\bin\calc.dll"`, and there are no image load events showing this DLL being loaded into any process. This suggests the technique may have failed to execute completely, possibly due to Windows Defender intervention or missing dependencies.

Missing are any process creation events where the ParentProcessGuid or ParentProcessId fields show unexpected values that would indicate successful parent PID spoofing. The normal process tree relationships remain intact throughout the capture window.

## Assessment

This dataset provides moderate value for detection engineering, primarily as an example of attempted parent PID spoofing rather than successful execution. The PowerShell scriptblock logging captures the complete attack script, making it excellent for content-based detection rules. The Security event 4703 privilege adjustment logging provides clear indicators of processes acquiring dangerous privileges necessary for process manipulation.

The Sysmon process access events (EID 10) with full access rights (0x1FFFFF) offer good behavioral indicators, especially when correlated with PowerShell execution. However, the apparent failure of the actual spoofing technique limits the dataset's utility for testing detection logic that focuses on the end result (anomalous parent-child relationships).

For a more complete dataset, successful execution showing iexplore.exe created with explorer.exe as the apparent parent would provide the critical evidence needed to test detection rules focused on process tree anomalies.

## Detection Opportunities Present in This Data

1. PowerShell scriptblock content detection for "PPID-Spoof" function calls and parent PID manipulation scripts
2. Privilege escalation detection on Security event 4703 with SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege being enabled
3. Suspicious process access patterns where PowerShell processes access other processes with 0x1FFFFF (full access) rights
4. PowerShell command line analysis for scripts referencing process creation APIs and parent PID manipulation
5. Behavioral analysis of PowerShell processes accessing multiple other processes in rapid succession
6. File path analysis for references to offensive security tools like "AtomicRedTeam" in command lines
7. PowerShell execution context anomalies where scripts load and execute external PowerShell files with process manipulation capabilities
