# T1055.004-1: Asynchronous Procedure Call — Process Injection via C#

## Technique Context

T1055.004 (Asynchronous Procedure Call) is a process injection sub-technique where attackers inject and execute code in another process using Windows' Asynchronous Procedure Call (APC) mechanism. APCs are a Windows feature that allows threads to execute code asynchronously when they enter an alertable wait state. Attackers leverage this by queuing malicious code to execute in a target process's thread context, achieving code execution while potentially evading detection by running within a legitimate process.

The detection community focuses on monitoring for cross-process activity, particularly suspicious process access patterns with high privilege levels (PROCESS_ALL_ACCESS or similar), unusual call traces involving APC-related Windows APIs (QueueUserAPC, NtQueueApcThread), and .NET-based injection techniques that leverage managed code to perform native process manipulation.

## What This Dataset Contains

This dataset captures a C#-based APC injection test that demonstrates clear process injection activity. The Security channel shows the execution chain with process creation events for cmd.exe (PID 23700) executing `"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1055.004\bin\T1055.exe"` and whoami.exe (PID 23972) with command line `"C:\Windows\system32\whoami.exe"`.

The most significant evidence comes from Sysmon EID 10 (Process Access) events showing PowerShell accessing both target processes with full access rights (GrantedAccess: 0x1FFFFF). The call traces reveal .NET Framework involvement, particularly System.Management.Automation components in the injection pathway. For the whoami.exe target, the call trace shows: `C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\e742dd873d3be63d30e85f1639febe4d\System.Management.Automation.ni.dll+11b5dd9`.

Sysmon EID 7 events capture extensive .NET Framework DLL loading in both PowerShell processes (PIDs 24420 and 25236), including clr.dll, mscorlib.ni.dll, clrjit.dll, and System.Management.Automation.ni.dll, consistent with managed code execution preparing for native process manipulation.

## What This Dataset Does Not Contain

The dataset lacks visibility into the actual APC injection executable (T1055.exe) because the cmd.exe process exits with status 0x1, indicating the injection tool likely failed to execute successfully or was blocked. No Sysmon ProcessCreate events capture T1055.exe execution, and no network connections, file drops, or other post-injection artifacts are present.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass), providing no insight into the actual injection code or methodology. The failure to execute T1055.exe means we see the setup and targeting phases of the injection attempt but not the payload execution or its effects.

Windows Defender's active real-time protection may have contributed to blocking the injection executable, though no explicit ACCESS_DENIED events are visible in this dataset.

## Assessment

This dataset provides excellent telemetry for detecting the reconnaissance and targeting phases of APC injection attempts, particularly .NET-based implementations. The Sysmon process access events with detailed call traces offer high-fidelity detection opportunities that would be difficult for attackers to evade. The correlation between PowerShell execution, .NET Framework loading, and cross-process access patterns creates a strong detection foundation.

However, the dataset's value is limited by the apparent failure of the injection payload to execute, meaning defenders cannot study the complete attack lifecycle or post-injection behaviors. The telemetry quality is high for what's present, but the truncated execution reduces its utility for understanding full APC injection techniques.

## Detection Opportunities Present in This Data

1. **Cross-process access from PowerShell with full privileges** - Monitor Sysmon EID 10 where powershell.exe accesses other processes with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS)

2. **.NET Framework call traces in process access events** - Alert on Sysmon EID 10 CallTrace fields containing System.Management.Automation.ni.dll references combined with process access

3. **PowerShell spawning system utilities followed by process access** - Correlate Security EID 4688 showing powershell.exe creating whoami.exe or cmd.exe with subsequent Sysmon EID 10 process access events

4. **Suspicious process access timing patterns** - Detect process access events occurring immediately after target process creation (within seconds) as shown by the timestamps

5. **PowerShell loading injection-related .NET assemblies** - Monitor Sysmon EID 7 for PowerShell loading clr.dll, clrjit.dll, and System.Management.Automation components in rapid succession

6. **Command line patterns indicating injection tools** - Alert on Security EID 4688 with command lines referencing AtomicRedTeam paths or executables named with technique IDs (T1055.exe)
