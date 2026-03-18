# T1055.004-2: Asynchronous Procedure Call — EarlyBird APC Queue Injection in Go

## Technique Context

T1055.004 - Asynchronous Procedure Call is a process injection technique that leverages Windows APC (Asynchronous Procedure Call) queues to execute code in the context of another process. Early Bird APC injection specifically targets processes during their initialization phase, before their main thread begins execution, making it particularly stealthy. Attackers use this technique to inject shellcode or DLLs into legitimate processes to evade detection, execute malicious code with different process privileges, or hide malicious activity within trusted processes.

The detection community focuses on monitoring for suspicious process access patterns, unusual memory allocations, and API calls associated with process injection. Key indicators include OpenProcess calls with specific access rights (PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD), QueueUserAPC API calls, and suspicious cross-process memory operations.

## What This Dataset Contains

This dataset captures a Go-based EarlyBird APC injection test using the command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055.004\bin\x64\EarlyBird.exe -program \"C:\Windows\System32\werfault.exe\" -debug}`. The data shows:

**Process Creation Chain**: Security 4688 events show PowerShell spawning the EarlyBird.exe process, then accessing whoami.exe (PID 26520) and another PowerShell instance (PID 26496).

**Process Access Events**: Two critical Sysmon EID 10 events capture the injection activity:
- PowerShell (PID 25508) accessing whoami.exe (PID 26520) with GrantedAccess 0x1FFFFF (full access rights)
- PowerShell (PID 25508) accessing another PowerShell process (PID 26496) with the same full access rights

**PowerShell Scriptblock Logging**: EID 4104 events capture the actual command execution: `& {C:\AtomicRedTeam\atomics\T1055.004\bin\x64\EarlyBird.exe -program "C:\Windows\System32\werfault.exe" -debug}` and related execution context.

**Image Loading Events**: Multiple Sysmon EID 7 events show .NET framework components and Windows Defender DLLs being loaded into PowerShell processes, tagged with process injection rule names.

## What This Dataset Does Not Contain

The dataset is missing several key elements for complete process injection telemetry:

**Missing Sysmon ProcessCreate Events**: The EarlyBird.exe and werfault.exe processes are not captured in Sysmon EID 1 events due to the include-mode filtering of the sysmon-modular configuration, which only captures known-suspicious process patterns.

**No Memory Allocation Events**: Sysmon doesn't provide events for VirtualAllocEx or WriteProcessMemory operations that would be core to the injection process.

**Missing API-Level Details**: No events capture the specific APC queue manipulation (QueueUserAPC calls) or thread context switching that defines this technique.

**Limited Network/Registry Activity**: The dataset shows minimal secondary artifacts beyond the core injection events, suggesting the injected payload may not have performed additional malicious actions.

## Assessment

This dataset provides solid evidence of process injection activity through Sysmon process access events and PowerShell execution logging. The Security 4688/4689 events offer complete process lifecycle tracking with command lines, while Sysmon EID 10 events capture the critical cross-process access patterns with full access rights (0x1FFFFF) that indicate injection attempts. However, the dataset lacks granular API-level telemetry and the target process creation events, limiting deep forensic analysis of the injection mechanism itself. The PowerShell script block logging provides clear attack attribution and command reconstruction capabilities.

## Detection Opportunities Present in This Data

1. **Process Access with Full Rights**: Alert on Sysmon EID 10 events where GrantedAccess equals 0x1FFFFF, especially from scripting engines like PowerShell accessing system utilities
2. **PowerShell Execution of Injection Tools**: Monitor Security 4688 command lines containing paths to known injection tools or suspicious executables with injection-related arguments like "-debug"
3. **Cross-Process Memory Access from PowerShell**: Detect PowerShell processes accessing other processes with high-privilege access rights, particularly system utilities
4. **PowerShell Script Block Injection Patterns**: Hunt for EID 4104 events containing execution of binaries from AtomicRedTeam paths or tools with process injection capabilities
5. **Unusual Process Access Chains**: Correlate Sysmon EID 10 events where the same source process accesses multiple different target processes within short time windows
6. **CallTrace Analysis for Injection**: Examine the CallTrace field in process access events for patterns indicating .NET/PowerShell-originated process manipulation
7. **Token Privilege Escalation Correlation**: Combine Security EID 4703 privilege adjustment events with subsequent process access events to identify privilege abuse for injection
