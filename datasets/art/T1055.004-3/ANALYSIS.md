# T1055.004-3: Asynchronous Procedure Call — Remote Process Injection with Go using NtQueueApcThreadEx WinAPI

## Technique Context

T1055.004 (Asynchronous Procedure Call) is a process injection technique where attackers queue Asynchronous Procedure Calls (APCs) to execute malicious code in the context of another process. This technique leverages Windows' APC mechanism, which allows threads to execute code asynchronously when they enter an alertable wait state. The detection community focuses on monitoring for process access events with specific access rights (particularly PROCESS_VM_WRITE, PROCESS_VM_OPERATION, and THREAD_SET_CONTEXT), unusual cross-process memory operations, and suspicious API calls like NtQueueApcThread or NtQueueApcThreadEx.

This specific test simulates a Go-based implementation using the NtQueueApcThreadEx API, representing how modern malware might leverage this technique for defense evasion and privilege escalation by injecting code into legitimate processes.

## What This Dataset Contains

The dataset captures a successful APC injection test execution with clear evidence of cross-process activity:

**PowerShell Command Execution**: Security event 4688 shows the PowerShell command `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055.004\bin\x64\NtQueueApcThreadEx.exe -debug}` launching the injection tool.

**Process Creation Chain**: Sysmon captures the process hierarchy with process IDs 26800 (parent PowerShell) → 27964 (child PowerShell) and a whoami.exe process (26616) used as a target.

**Cross-Process Access**: Two critical Sysmon Event ID 10 (Process Accessed) events show the injection activity:
- Source process 26800 (PowerShell) accessing target 26616 (whoami.exe) with GrantedAccess `0x1FFFFF` (full access)
- Source process 26800 accessing target 27964 (PowerShell) with the same access rights

**Call Stack Evidence**: The CallTrace field reveals the injection path through `ntdll.dll+a2854|KERNELBASE.dll+47734` leading to `System.Management.Automation.ni.dll`, indicating PowerShell's involvement in the process access.

**DLL Loading Activity**: Sysmon Event ID 7 events show multiple .NET runtime DLLs (mscoree.dll, mscoreei.dll, clr.dll) being loaded by the target processes, consistent with PowerShell execution.

## What This Dataset Does Not Contain

The dataset is missing the actual `NtQueueApcThreadEx.exe` process creation event, likely because the sysmon-modular configuration's include-mode filtering doesn't match this custom binary. The Security channel provides the PowerShell command line but not the direct execution of the injection tool.

There are no network connections or registry modifications, suggesting this test focuses purely on the local process injection mechanism without additional persistence or communication activities.

The dataset lacks specific APC-related API calls or memory allocation events that would typically be visible in more detailed process monitoring tools, as standard Windows logging doesn't capture these low-level operations.

## Assessment

This dataset provides excellent telemetry for detecting APC injection attacks. The combination of Sysmon Event ID 10 (Process Accessed) with full access rights (`0x1FFFFF`) and Security Event ID 4688 command-line logging creates a strong detection foundation. The call stack information in the process access events adds valuable context for attribution and technique identification.

The data quality is high for building behavioral detections around suspicious cross-process access patterns, especially when correlating PowerShell execution with process access events. However, the missing process creation event for the actual injection tool represents a gap that defenders should account for by ensuring comprehensive process creation logging beyond Sysmon's filtered approach.

## Detection Opportunities Present in This Data

1. **Cross-Process Access with Full Rights**: Alert on Sysmon Event ID 10 where GrantedAccess equals `0x1FFFFF` (PROCESS_ALL_ACCESS), particularly from PowerShell processes to other executables.

2. **PowerShell Process Access Correlation**: Detect PowerShell processes (Event ID 1 or 4688) followed by suspicious process access events (Event ID 10) within a short time window.

3. **Command Line Pattern Matching**: Monitor Security Event ID 4688 for command lines containing paths to `\atomics\` directories or executables with injection-related names like "ApcThread" or "QueueApc".

4. **Unusual Parent-Child Process Access**: Flag scenarios where a parent process accesses child processes with high-privilege access rights, particularly in PowerShell execution contexts.

5. **Call Stack Analysis**: Use the CallTrace field in Event ID 10 to identify injection attempts originating from .NET assemblies or PowerShell automation libraries.

6. **Process Access to Short-Lived Processes**: Correlate process creation and termination events with process access events to identify injection into processes that exit quickly after being accessed.
