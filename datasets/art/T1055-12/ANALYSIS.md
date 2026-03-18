# T1055-12: Process Injection — Process Injection with Go using CreateThread WinAPI (Natively)

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where adversaries inject code into processes to evade process-based defenses and elevate privileges. This specific test (T1055-12) demonstrates process injection using a Go-based tool that leverages the CreateThread Windows API natively. The technique is commonly used by malware to hide malicious code within legitimate processes, bypass security controls, and maintain persistence. Detection engineering typically focuses on process access events with high-privilege access rights, unusual cross-process activity, and the loading of unexpected DLLs or execution of injected code.

## What This Dataset Contains

The dataset captures a Go-based process injection test executed via PowerShell. The key telemetry shows:

**Process Creation Chain**: Security 4688 events show powershell.exe (PID 16312) spawning another powershell.exe instance (PID 14816) with command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThreadNative.exe -debug}` and a whoami.exe process (PID 16176).

**Process Access Events**: Two critical Sysmon 10 events capture the injection behavior. The first shows powershell.exe (PID 16312) accessing whoami.exe (PID 16176) with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS), and the second shows access to the spawned powershell.exe (PID 14816) with the same high-privilege access rights.

**PowerShell Telemetry**: PowerShell 4104 script block logs capture the execution command `C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThreadNative.exe -debug`, indicating the Go injection tool was invoked.

**DLL Loading Activity**: Extensive Sysmon 7 events show .NET runtime DLLs (mscoree.dll, mscoreei.dll, clr.dll) being loaded into all PowerShell processes, along with Windows Defender components (MpOAV.dll, MpClient.dll).

## What This Dataset Does Not Contain

Notably missing is any Sysmon ProcessCreate (EID 1) event for the CreateThreadNative.exe binary itself. The sysmon-modular config uses include-mode filtering for ProcessCreate events, only capturing processes matching known-suspicious patterns. Since the Go injection tool doesn't match these patterns, its process creation wasn't logged. This represents a significant gap in visibility - we can see the PowerShell command that invokes the tool and the resulting injection behavior, but not the actual injector process.

The dataset also lacks any indication that Windows Defender blocked or detected the injection activity, suggesting the technique executed successfully without triggering real-time protection.

## Assessment

This dataset provides excellent visibility into the process injection behavior through Sysmon 10 events, which are the primary detection source for this technique. The process access events with PROCESS_ALL_ACCESS rights (0x1FFFFF) provide clear indicators of injection activity. The Security 4688 events with command-line logging offer good process chain visibility, and PowerShell script block logging captures the execution context.

However, the missing ProcessCreate event for the actual injection tool highlights a limitation in filtered Sysmon configurations. This could be problematic for comprehensive detection coverage, as defenders might miss the actual injector binary while only seeing the effects.

The dataset would be stronger with ETW-based process creation monitoring or a more permissive Sysmon ProcessCreate configuration to capture all process activity.

## Detection Opportunities Present in This Data

1. **High-Privilege Process Access**: Sysmon EID 10 events with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) from PowerShell to other processes, particularly short-lived processes like whoami.exe

2. **Cross-Process Access Patterns**: Process access where the source process accesses multiple different target processes in rapid succession, indicating potential process enumeration for injection

3. **PowerShell Command Line Indicators**: Security EID 4688 with command lines containing suspicious binary paths like `\AtomicRedTeam\atomics\T1055\bin\` or references to injection-related tools

4. **Script Block Logging for Injection Tools**: PowerShell EID 4104 containing references to known injection utilities or suspicious binary executions with debugging flags like `-debug`

5. **Process Access Call Stack Analysis**: Sysmon EID 10 CallTrace field showing .NET runtime components (System.ni.dll, System.Management.Automation.ni.dll) in the call stack when accessing external processes

6. **Abnormal PowerShell Process Relationships**: Parent-child relationships where PowerShell spawns another PowerShell instance followed immediately by process access events to third-party processes
