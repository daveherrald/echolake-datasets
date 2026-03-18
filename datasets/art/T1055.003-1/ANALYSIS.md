# T1055.003-1: Thread Execution Hijacking — Thread Execution Hijacking

## Technique Context

Thread Execution Hijacking (T1055.003) is a process injection technique where attackers suspend a target process thread, modify its context to point to malicious code, then resume execution. Unlike other injection methods that create new threads or allocate new memory, thread hijacking leverages existing threads in running processes, making it harder to detect through traditional monitoring of thread creation events.

Attackers use this technique to execute code within the address space of legitimate processes, inheriting their privileges and evading process-based detection. The detection community typically focuses on process access events with specific access rights (PROCESS_SUSPEND_RESUME, PROCESS_VM_WRITE, PROCESS_VM_OPERATION), unusual cross-process thread operations, and processes accessing other processes they normally wouldn't interact with.

## What This Dataset Contains

This dataset captures a failed thread execution hijacking attempt. The core evidence shows PowerShell attempting to execute code that references a missing injection tool:

**PowerShell Script Block (EID 4104)**: The attack script is clearly visible: `{$notepad = Start-Process notepad -passthru\nStart-Process \"C:\AtomicRedTeam\atomics\T1055.003\bin\InjectContext.exe\"\nStart-Sleep -Seconds 5\nStop-Process $notepad.id}`

**PowerShell Error (EID 4100)**: The injection tool fails to execute with "This command cannot be run due to the error: The system cannot find the file specified" for `C:\AtomicRedTeam\atomics\T1055.003\bin\InjectContext.exe`

**Process Creation Events**: Security EID 4688 shows notepad.exe (PID 0x5920) being created as the intended injection target, and Sysmon EID 1 captures the same process creation with full command line details.

**Process Access Events**: Three Sysmon EID 10 events show PowerShell (PID 23252 and 21944) accessing other processes with high-privilege access rights (0x1FFFFF and 0x1F3FFF), including access to the notepad target process. These events include detailed call traces through .NET assemblies.

**Process Termination**: The notepad target process exits with status 0xFFFFFFFF, indicating forced termination via the PowerShell Stop-Process command.

## What This Dataset Does Not Contain

The actual thread execution hijacking behavior is missing because the injection executable (`InjectContext.exe`) was not present on the system. This means the dataset lacks:

- The actual SetThreadContext or GetThreadContext API calls that would indicate thread manipulation
- Memory allocation/writing events in the target process
- Thread suspension and resumption events
- Any evidence of successful code injection or execution within the target process

The Sysmon ProcessCreate events for the primary PowerShell processes are missing due to the sysmon-modular config's include-mode filtering, which only captures processes matching suspicious patterns. However, Security 4688 events provide complete process creation coverage with command-line logging.

## Assessment

This dataset provides moderate value for detection engineering, primarily as a "failed attempt" scenario. While it doesn't contain the complete attack chain, it captures the preparatory activities and process interactions that would occur before the actual injection. The process access events with high privilege levels (0x1FFFFF, 0x1F3FFF) against unrelated processes like notepad are particularly valuable indicators.

The dataset would be significantly stronger with a working injection tool that could demonstrate the complete technique, including thread context manipulation and successful code execution. However, the current telemetry is still useful for detecting reconnaissance and preparation phases of thread hijacking attacks.

## Detection Opportunities Present in This Data

1. **PowerShell script blocks referencing injection tools or process manipulation** - EID 4104 contains explicit references to injection executables and process control operations

2. **High-privilege cross-process access patterns** - Sysmon EID 10 events showing PowerShell accessing unrelated processes (notepad, whoami) with extensive access rights (0x1FFFFF, 0x1F3FFF)

3. **PowerShell error messages indicating missing injection tools** - EID 4100 errors for files in suspicious paths like `\atomics\T1055.003\bin\`

4. **Process creation followed by immediate termination patterns** - Creation of notepad followed by forced termination (exit code 0xFFFFFFFF) within seconds

5. **PowerShell executing with Start-Process and Stop-Process cmdlets targeting other processes** - Command line patterns showing process lifecycle manipulation

6. **Call trace analysis in process access events** - Stack traces through .NET assemblies (System.Management.Automation.ni.dll) indicating PowerShell-based process interaction

7. **Named pipe creation by PowerShell processes** - Sysmon EID 17 showing PowerShell creating communication pipes that could be used for injection coordination
