# T1055-5: Process Injection — Read-Write-Execute process Injection

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where attackers inject arbitrary code into the address space of a separate live process. The "Read-Write-Execute" variant specifically refers to injecting code into memory regions that have read, write, and execute permissions - a dangerous combination that allows both code modification and execution. This technique helps attackers evade process-based defenses, maintain persistence, and potentially elevate privileges by leveraging the security context of the target process.

The detection community focuses on monitoring for suspicious process access patterns, particularly cross-process memory operations with dangerous permission combinations like PROCESS_ALL_ACCESS (0x1FFFFF), unexpected image loads, and behavioral anomalies in targeted processes. Key indicators include process hollowing, DLL injection, and memory allocation patterns consistent with shellcode injection.

## What This Dataset Contains

This dataset captures a PowerShell-based process injection test that demonstrates the complete attack chain:

**Primary Attack Vector**: The dataset shows PowerShell executing a multi-stage injection attack via the command: `"powershell.exe" & {$address = (& \"C:\AtomicRedTeam\atomics\T1055\bin\x64\searchVuln.exe\" \"C:\AtomicRedTeam\atomics\T1055\bin\x64\vuln_dll\\\" | Out-String | Select-String -Pattern \"VirtualAddress: (\w+)\").Matches.Groups[1].Value & \"C:\AtomicRedTeam\atomics\T1055\bin\x64\RWXinjectionLocal.exe\" \"C:\AtomicRedTeam\atomics\T1055\bin\x64\vuln_dll\msys-2.0.dll\" $address}`

**Process Access Evidence**: Sysmon EID 10 events show clear injection attempts with PowerShell (PID 44068) accessing both whoami.exe (PID 44508) and another PowerShell instance (PID 44576) with full access rights (GrantedAccess: 0x1FFFFF). The call traces reveal .NET Framework involvement in the injection process.

**Process Creation Chain**: Security EID 4688 and Sysmon EID 1 events document the complete process hierarchy, showing PowerShell spawning whoami.exe and additional PowerShell instances as part of the attack sequence.

**Image Load Monitoring**: Multiple Sysmon EID 7 events capture suspicious DLL loads, including .NET runtime components (mscoree.dll, mscoreei.dll, clr.dll) and Windows Defender components (MpOAV.dll, MpClient.dll) being loaded into the injecting PowerShell processes.

## What This Dataset Does Not Contain

**Missing Core Injection Executables**: The sysmon-modular configuration's include-mode filtering means we don't see ProcessCreate events for `searchVuln.exe` or `RWXinjectionLocal.exe` - the actual injection tools. These custom executables didn't match the known-suspicious patterns in the Sysmon config.

**No Memory Allocation Events**: Sysmon doesn't capture the actual VirtualAllocEx or WriteProcessMemory calls that would show the memory manipulation aspects of the injection.

**Limited PowerShell Script Content**: The PowerShell channel (EID 4104) contains mostly test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual injection payload details, with only one meaningful script block showing the attack command structure.

**No Network or File System Impact**: The injection appears to be purely in-memory without creating persistent artifacts or network connections that would generate additional telemetry.

## Assessment

This dataset provides excellent visibility into the process-level behaviors of RWX injection attacks. The combination of Sysmon process access monitoring (EID 10) and process creation events (EID 1) delivers the core detection opportunities needed to identify injection attempts. The Security channel's command-line logging (EID 4688) compensates for the Sysmon ProcessCreate filtering limitations by capturing the full attack command line.

The telemetry quality is strong for building behavioral detections around suspicious process access patterns and cross-process interactions. However, the dataset would benefit from memory allocation events and more granular script block logging to capture the technical details of the injection methodology.

## Detection Opportunities Present in This Data

1. **Suspicious Process Access Patterns**: Monitor Sysmon EID 10 for processes accessing others with full privileges (0x1FFFFF) combined with .NET Framework call traces indicating programmatic injection attempts.

2. **PowerShell Command Line Analysis**: Detect Security EID 4688 events with PowerShell command lines containing process injection tool patterns, particularly references to "RWXinjection" executables and memory address parsing logic.

3. **Cross-Process PowerShell Spawning**: Alert on PowerShell processes creating additional PowerShell instances while simultaneously performing process access operations, indicating potential injection-based lateral movement.

4. **Anomalous DLL Load Sequences**: Correlate Sysmon EID 7 events showing rapid loading of .NET runtime DLLs (mscoree.dll, mscoreei.dll, clr.dll) in processes that don't typically require managed code execution.

5. **Process Hollowing Indicators**: Monitor for process creation immediately followed by cross-process access with high privileges, particularly when the accessing process loads injection-related libraries.

6. **PowerShell Profile Anomalies**: Track Sysmon EID 11 file creation events for PowerShell profile data in system contexts, which may indicate process injection frameworks establishing persistence.
