# T1055-7: Process Injection — Process Injection with Go using EtwpCreateEtwThread WinAPI

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where adversaries inject code into legitimate processes to evade detection, gain persistence, or elevate privileges. This specific test (T1055-7) focuses on using the EtwpCreateEtwThread Windows API through a Go-based implementation, which is a less commonly observed injection method compared to traditional techniques like DLL injection or process hollowing.

EtwpCreateEtwThread is an undocumented Windows API function related to Event Tracing for Windows (ETW) that can be abused for process injection. The detection community primarily focuses on monitoring process access events with high privileges (PROCESS_ALL_ACCESS or 0x1FFFFF), cross-process thread creation, and suspicious API calls from unexpected processes. This technique is particularly interesting because it leverages ETW infrastructure, which is typically associated with legitimate system monitoring and debugging activities.

## What This Dataset Contains

The dataset captures a PowerShell-based execution of the EtwpCreateEtwThread injection tool with the following key events:

**Process Chain**: The test executes through PowerShell with the command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\EtwpCreateEtwThread.exe -debug}` (Security EID 4688).

**Process Access Events**: Two critical Sysmon EID 10 events show the injection attempts:
- PowerShell (PID 8784) accessing whoami.exe (PID 43788) with GrantedAccess 0x1FFFFF (full access)
- PowerShell (PID 8784) accessing another PowerShell process (PID 8816) with GrantedAccess 0x1FFFFF

**Target Processes**: The injection targets both `whoami.exe` and another `powershell.exe` process, demonstrating cross-process access patterns typical of process injection techniques.

**Image Load Events**: Extensive Sysmon EID 7 events capture .NET runtime loading (mscoree.dll, mscoreei.dll, clr.dll) across multiple PowerShell processes, showing the managed code execution environment.

**PowerShell Telemetry**: Script block logging (EID 4104) captures the execution command `{C:\AtomicRedTeam\atomics\T1055\bin\x64\EtwpCreateEtwThread.exe -debug}` along with test framework boilerplate.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide deeper insight into the injection technique:

**Missing EtwpCreateEtwThread.exe Process Creation**: No Sysmon EID 1 event for the actual injection tool execution, likely because it's not in the sysmon-modular include list for ProcessCreate filtering.

**No Thread Creation Events**: Missing Sysmon EID 8 (CreateRemoteThread) events that would show the actual thread injection into target processes.

**Limited API Call Visibility**: No detailed API call tracing that would show the specific EtwpCreateEtwThread function calls and parameters.

**Injected Code Evidence**: No file system artifacts or memory indicators showing what code was injected into the target processes.

**ETW-Specific Telemetry**: Missing ETW provider registration or trace session events that might indicate abuse of the ETW infrastructure.

## Assessment

This dataset provides moderate utility for detection engineering focused on process injection techniques. The Sysmon EID 10 events with PROCESS_ALL_ACCESS (0x1FFFFF) from PowerShell to multiple target processes represent strong behavioral indicators that are consistent with process injection attempts. The process access patterns, combined with the PowerShell command line containing the injection tool path, create a detectable sequence.

However, the dataset's detection value is limited by missing visibility into the actual injection mechanism. Without process creation events for the EtwpCreateEtwThread.exe binary or thread creation events, defenders cannot observe the complete attack chain or build signatures around the specific API abuse patterns that make this technique unique.

The data sources captured here (Sysmon process access, Security process creation, PowerShell logging) provide sufficient coverage for building high-level behavioral detections but lack the granular visibility needed for technique-specific detection rules.

## Detection Opportunities Present in This Data

1. **High-Privilege Process Access from PowerShell**: Sysmon EID 10 events showing PowerShell accessing other processes with GrantedAccess 0x1FFFFF, particularly when targeting system utilities like whoami.exe or other PowerShell instances.

2. **Command Line Execution Pattern**: Security EID 4688 and PowerShell EID 4104 showing execution of tools from the AtomicRedTeam directory structure, specifically `C:\AtomicRedTeam\atomics\T1055\bin\x64\EtwpCreateEtwThread.exe`.

3. **Cross-Process Access Between Related Processes**: Process access events where the source and target are both PowerShell processes but with different PIDs, indicating potential lateral movement or injection between PowerShell instances.

4. **PowerShell ScriptBlock with Injection Tool Execution**: PowerShell EID 4104 script block logging capturing direct execution of known process injection tools with debug parameters.

5. **Multiple Process Access Events in Sequence**: Temporal correlation of multiple Sysmon EID 10 events from the same source process accessing different targets within a short time window, indicating systematic process scanning or injection attempts.

6. **Privilege Token Adjustment**: Security EID 4703 showing extensive privilege enablement (SeAssignPrimaryTokenPrivilege, SeSecurityPrivilege, etc.) in PowerShell processes that subsequently perform process access operations.
