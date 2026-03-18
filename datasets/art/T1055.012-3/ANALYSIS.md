# T1055.012-3: Process Hollowing — Process Hollowing in Go using CreateProcessW WinAPI

## Technique Context

Process Hollowing (T1055.012) is a sophisticated process injection technique where attackers create a legitimate process in a suspended state, replace its memory contents with malicious code, and resume execution. The technique involves creating a process with CREATE_SUSPENDED flag, unmapping the original executable's memory, allocating new memory, writing malicious code, and updating the thread context to point to the injected code. This technique is particularly effective for evasion because the process appears legitimate from a process listing perspective while executing attacker-controlled code.

The detection community focuses on several indicators: process creation with CREATE_SUSPENDED flag, memory manipulation APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext), cross-process memory operations, and anomalous process behavior where the executed code differs significantly from the expected binary. This specific test uses a Go-based implementation targeting werfault.exe, a legitimate Windows Error Reporting process commonly abused for process hollowing due to its trusted nature.

## What This Dataset Contains

This dataset captures a process hollowing attempt that appears to have been blocked or failed. The telemetry shows:

**Process Creation Chain:**
- Security EID 4688: PowerShell process created with command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcess.exe -program \"C:\Windows\System32\werfault.exe\" -debug}`
- Sysmon EID 1: Same PowerShell process creation with detailed metadata
- Sysmon EID 1: whoami.exe execution for system discovery

**Cross-Process Access Attempts:**
- Sysmon EID 10: Process access events showing PowerShell accessing both whoami.exe and another PowerShell process with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS)
- Call stacks indicating .NET System.Management.Automation involvement

**Process Initialization:**
- Multiple Sysmon EID 7 events showing .NET runtime DLL loads (mscoree.dll, mscoreei.dll, clr.dll) across multiple PowerShell processes
- Sysmon EID 17 events showing PowerShell named pipe creation
- Security EID 4703: Token privilege adjustment enabling multiple high-privilege rights including SeAssignPrimaryTokenPrivilege

**PowerShell Activity:**
- PowerShell EID 4104: Script block showing the actual command execution: `& {C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcess.exe -program "C:\Windows\System32\werfault.exe" -debug}`

## What This Dataset Does Not Contain

The dataset lacks critical evidence of successful process hollowing:

**Missing Target Process Creation:** There are no Sysmon EID 1 events showing werfault.exe being created in a suspended state, suggesting the CreateProcess.exe tool either failed to execute or was blocked by Windows Defender.

**No Memory Manipulation Evidence:** The dataset contains no Sysmon EID 8 (CreateRemoteThread) events or indicators of memory allocation/modification in the target process, which would be expected during successful process hollowing.

**Limited Process Access Telemetry:** While cross-process access events exist, they only show PowerShell accessing other PowerShell processes and whoami.exe, not the intended werfault.exe target.

**No Hollowing-Specific APIs:** The absence of API calls typically associated with process hollowing (VirtualAllocEx, WriteProcessMemory, SetThreadContext) suggests the technique didn't progress beyond initial process creation attempts.

**Blocked Execution Indicators:** The Security event logs show normal process termination (exit status 0x0) without evidence of the CreateProcess.exe tool successfully executing its intended functionality.

## Assessment

This dataset provides moderate value for detection engineering, primarily capturing the preparatory phases of a process hollowing attempt rather than the technique itself. The telemetry effectively demonstrates how modern EDR solutions can detect and potentially block sophisticated injection techniques before they achieve their objectives. The cross-process access events and privilege escalation indicators offer solid detection opportunities, though they represent early-stage activities rather than the core hollowing behavior.

The dataset's strength lies in showing realistic attack preparation and the interaction between PowerShell-based execution frameworks and Go-based injection tools. However, its limitation is the lack of successful technique execution, which means detections built from this data would focus on attempt detection rather than impact assessment.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Command Line Patterns** - Security EID 4688 command lines containing references to process injection tools in AtomicRedTeam paths with suspicious parameters like "-debug" flag
2. **Cross-Process Memory Access from PowerShell** - Sysmon EID 10 events showing PowerShell processes accessing other processes with PROCESS_ALL_ACCESS (0x1FFFFF) rights
3. **Privilege Escalation for Process Manipulation** - Security EID 4703 events showing PowerShell enabling SeAssignPrimaryTokenPrivilege and other process-related privileges
4. **Suspicious Process Access Patterns** - Multiple Sysmon EID 10 events from the same source process accessing different targets in rapid succession
5. **PowerShell Script Block Execution of Injection Tools** - PowerShell EID 4104 showing execution of binaries with process injection-related parameters
6. **Anomalous .NET Runtime Loading Patterns** - Multiple Sysmon EID 7 events showing rapid .NET framework initialization across multiple PowerShell processes, potentially indicating automated injection attempts
