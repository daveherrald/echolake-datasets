# T1055-4: Process Injection — Dirty Vanity Process Injection

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where attackers inject code into legitimate processes to evade detection and potentially gain higher privileges. The "Dirty Vanity" variant referenced in this test involves injecting code into a running process using a specific implementation. Process injection is fundamental to many advanced attacks, allowing malware to hide within legitimate processes, inherit their permissions, and bypass application whitelisting or behavioral monitoring that focuses on process names rather than injected content.

Detection engineers typically focus on suspicious process access patterns, memory allocation behaviors, cross-process memory writes, and API calls like OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread. The technique often generates process access events (Sysmon EID 10) with high-privilege access masks, particularly when combined with DLL injection patterns.

## What This Dataset Contains

This dataset captures a failed attempt at "Dirty Vanity" process injection. The PowerShell command attempts to execute `"C:\AtomicRedTeam\atomics\T1055\bin\x64\redVanity.exe"` with a target process ID from a spawned calc.exe process: `{Start-Process "C:\AtomicRedTeam\atomics\T1055\bin\x64\redVanity.exe" (Start-Process calc.exe -PassThru).Id}`.

Key events include:
- Security EID 4688 shows PowerShell process creation with the injection command line
- Security EID 4688 captures calc.exe creation (PID 42416) as the intended target process
- Sysmon EID 10 process access events show PowerShell (PID 42444) accessing both whoami.exe (PID 42324) and the spawned PowerShell process (PID 42052) with full access rights (GrantedAccess: 0x1FFFFF)
- PowerShell EID 4100 error indicates the injection tool failed: "This command cannot be run due to the error: The system cannot find the file specified"
- Multiple Sysmon EID 7 image load events show .NET runtime components and Windows Defender modules loading into PowerShell processes

The process access events show legitimate injection-related API patterns, with call traces through ntdll.dll, KERNELBASE.dll, and System.Management.Automation components, suggesting PowerShell's Start-Process cmdlet attempted process manipulation before the tool execution failed.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful process injection because the redVanity.exe tool was not found on the system. Consequently, there are no:
- Sysmon EID 8 (CreateRemoteThread) events indicating successful thread injection
- Memory allocation events in target processes
- Evidence of injected code execution within calc.exe or other target processes
- Network connections or file operations from injected code
- Registry modifications typical of persistent injection techniques

The failure occurred at the file system level before any actual injection APIs were called, limiting the injection-specific telemetry to the initial process access attempts.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating the preparatory phases of process injection rather than the complete technique. The Sysmon EID 10 process access events with high-privilege access masks (0x1FFFFF) are the strongest indicators of injection attempts, combined with suspicious PowerShell command lines containing process ID manipulation.

The Security channel's command-line logging proves invaluable here, capturing the exact injection attempt syntax that many attackers use. The combination of PowerShell process creation, immediate calc.exe spawning, and subsequent high-privilege process access creates a clear behavioral pattern useful for detection rules.

However, the dataset's value is limited by the execution failure - defenders need successful injection examples to understand complete attack telemetry and develop comprehensive detection strategies that cover both failed and successful attempts.

## Detection Opportunities Present in This Data

1. **PowerShell command line analysis** - Security EID 4688 events showing Start-Process cmdlets with suspicious patterns like process ID injection and external executable references
2. **Process access anomalies** - Sysmon EID 10 events where PowerShell processes access other processes with full privileges (0x1FFFFF), especially combined with injection-related call traces
3. **Temporal process correlation** - Rapid sequence of calc.exe creation followed immediately by process access from the spawning PowerShell instance
4. **Cross-process access from scripting engines** - PowerShell processes accessing non-child processes with high privileges, particularly when combined with Start-Process cmdlet usage
5. **File not found errors in process injection context** - PowerShell EID 4100 errors indicating missing injection tools, useful for detecting attempted but failed attacks
6. **Suspicious process spawning patterns** - Parent-child relationships where PowerShell spawns common target processes (calc.exe, notepad.exe) immediately before process access events
