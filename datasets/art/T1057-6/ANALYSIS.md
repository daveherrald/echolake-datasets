# T1057-6: Process Discovery — Discover Specific Process - tasklist

## Technique Context

T1057 Process Discovery is a fundamental reconnaissance technique where attackers enumerate running processes to understand system state, identify security tools, find interesting processes to target, or locate specific services. The technique is ubiquitous in both automated malware and manual intrusion activities.

This specific test (T1057-6) focuses on using `tasklist` with filtering to discover specific processes — in this case, searching for the "lsass" process. The LSASS (Local Security Authority Subsystem Service) process is a high-value target for credential dumping attacks, making its discovery a common precursor to T1003 techniques. The detection community focuses heavily on `tasklist` usage patterns, especially when combined with filtering commands like `findstr` or `grep`, as these indicate targeted process hunting rather than general system administration.

## What This Dataset Contains

This dataset captures a PowerShell-initiated process discovery chain that executes `cmd.exe /c tasklist | findstr lsass`. The complete execution flow is well-documented across all three log sources:

**Security Event Log (15 events):**
- Process creation chain: PowerShell (PID 11052) → cmd.exe (PID 39500) → tasklist.exe (PID 39924) and findstr.exe (PID 10452)  
- Command line `"cmd.exe" /c tasklist | findstr lsass` (Security EID 4688)
- Command line `tasklist` and `findstr lsass` for the child processes
- Process termination events (Security EID 4689) for all created processes
- Token privilege adjustment (Security EID 4703) showing PowerShell gaining administrative privileges

**Sysmon Events (31 events):**
- Process creation events (Sysmon EID 1) for whoami.exe, cmd.exe, tasklist.exe, and findstr.exe with full command lines and process relationships
- Process access events (Sysmon EID 10) showing PowerShell accessing both whoami.exe and cmd.exe processes
- Image load events (Sysmon EID 7) documenting DLL loading patterns for PowerShell, including .NET runtime components and Windows Defender integration
- File creation events (Sysmon EID 11) for PowerShell profile data
- Named pipe creation (Sysmon EID 17) for PowerShell host communication

**PowerShell Logs (34 events):**
- Standard test framework boilerplate with `Set-ExecutionPolicy Bypass` commands (PowerShell EID 4103)
- Script block creation events (PowerShell EID 4104) containing only error handling templates

## What This Dataset Does Not Contain

The PowerShell logs contain only framework boilerplate and do not capture the actual PowerShell commands that initiated the process discovery. This is because the test likely used simple process execution methods that don't generate PowerShell script block logging events.

The dataset lacks any blocked execution events or access denied errors, indicating Windows Defender did not interfere with this process discovery technique. There are no network connections or file system modifications beyond standard PowerShell profile management.

## Assessment

This dataset provides excellent telemetry for T1057 process discovery detection engineering. The Security log's command-line auditing capability captures the complete attack chain with full command arguments, while Sysmon adds crucial process relationship context and behavioral indicators through process access events. The combination offers multiple detection opportunities across different log sources.

The presence of both `tasklist` execution and the specific `findstr lsass` filtering makes this particularly valuable for detecting targeted process discovery rather than benign system administration. The process access events in Sysmon add an additional behavioral dimension that many detection teams overlook.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security EID 4688 events showing `tasklist | findstr` or similar filtering patterns, especially when targeting sensitive process names like "lsass"

2. **Process ancestry analysis** - Sysmon EID 1 events revealing PowerShell spawning cmd.exe with tasklist commands, indicating scripted reconnaissance 

3. **Process access correlation** - Sysmon EID 10 events showing PowerShell accessing newly created processes, suggesting programmatic process manipulation

4. **Rapid process creation sequences** - Multiple Security EID 4688 events within seconds showing reconnaissance tool execution patterns

5. **Privilege escalation correlation** - Security EID 4703 token adjustment events combined with subsequent process discovery, indicating elevated reconnaissance

6. **Pipeline command detection** - Security command-line fields containing pipe operators with system reconnaissance tools like tasklist, findstr, grep

7. **Parent-child process relationship analysis** - Sysmon parent process fields showing non-administrative tools spawning system reconnaissance utilities
