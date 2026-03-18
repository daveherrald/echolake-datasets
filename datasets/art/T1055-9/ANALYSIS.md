# T1055-9: Process Injection — Remote Process Injection with Go using CreateRemoteThread WinAPI

## Technique Context

T1055 Process Injection is a fundamental defense evasion and privilege escalation technique where attackers inject malicious code into the address space of legitimate processes. This specific test (T1055-9) demonstrates remote process injection using Go code that leverages the Windows CreateRemoteThread API. This technique is particularly valuable to attackers because it allows malicious code to execute within the context of legitimate processes, potentially bypassing application whitelisting and making detection more challenging. The detection community focuses heavily on process access patterns, memory allocation behaviors, and suspicious cross-process interactions that indicate injection attempts.

## What This Dataset Contains

The dataset captures a PowerShell-driven process injection attempt with clear evidence in multiple log sources:

**Security Events:**
- Security 4688 shows the PowerShell command line: `"powershell.exe" & {$process = Start-Process C:\Windows\System32\werfault.exe -passthru C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe -pid $process.Id -debug}`
- Process creation of the target process WerFault.exe (PID 12128)
- Process exits showing the WerFault.exe terminating with exit code 0x1 (failure)

**Sysmon Events:**
- EID 1 process creation events for whoami.exe, PowerShell processes, and WerFault.exe
- EID 10 process access events showing PowerShell (PID 11544) accessing whoami.exe (PID 10336) and another PowerShell process (PID 11500) with high privileges (GrantedAccess: 0x1FFFFF)
- The call stack in the EID 10 events shows .NET framework components, indicating managed code execution
- Multiple EID 7 image load events for .NET runtime components (mscoree.dll, mscoreei.dll, clr.dll) and PowerShell automation libraries

**PowerShell Logs:**
- EID 4104 script block showing the actual injection command: `$process = Start-Process C:\Windows\System32\werfault.exe -passthru C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThread.exe -pid $process.Id -debug`

## What This Dataset Does Not Contain

The dataset is missing critical evidence that would normally accompany successful process injection:

**Missing CreateRemoteThread Binary Execution:** There are no Sysmon EID 1 events showing the actual `CreateRemoteThread.exe` binary being executed, despite it being referenced in the PowerShell command line. This suggests the sysmon-modular configuration filtered out this process creation, or the execution failed early.

**No Memory Allocation Events:** The dataset lacks Sysmon EID 8 (CreateRemoteThread) events that would show the actual thread injection occurring in the target process.

**Limited Target Process Telemetry:** While WerFault.exe is created, there's minimal telemetry showing what happened within that process during the injection attempt.

**No Network or File System Evidence:** The injection attempt appears to have failed before establishing persistence or creating additional artifacts.

## Assessment

This dataset provides excellent telemetry for detecting the setup and attempt phases of process injection, but limited evidence of successful injection execution. The Security 4688 events with full command-line logging are particularly valuable, clearly showing the injection tooling and target process selection. The Sysmon EID 10 process access events demonstrate the high-privilege access patterns typical of injection attempts. However, the apparent failure of the injection (evidenced by WerFault.exe exit code 0x1) means this dataset is better suited for detecting injection attempts rather than successful injections. The combination of PowerShell script block logging and Security process auditing provides strong detection opportunities for this technique.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor EID 4104 events for script blocks containing process injection patterns like `Start-Process` combined with external injection tools and `-passthru` parameters

2. **Command Line Pattern Detection** - Alert on Security 4688 events with command lines referencing injection tools in suspicious paths like `\atomics\T1055\bin\` or containing patterns like `CreateRemoteThread.exe -pid`

3. **High-Privilege Process Access** - Monitor Sysmon EID 10 events where GrantedAccess equals 0x1FFFFF (PROCESS_ALL_ACCESS), especially from managed processes like PowerShell accessing system utilities

4. **Suspicious Process Ancestry** - Detect PowerShell processes spawning system utilities like WerFault.exe, whoami.exe, or other Windows binaries in rapid succession

5. **Cross-Process .NET Injection Patterns** - Monitor for process access events with call stacks containing System.Management.Automation.dll and KERNELBASE.dll indicating managed code performing process manipulation

6. **Failed Injection Indicators** - Alert on target processes (like WerFault.exe) that terminate with non-zero exit codes shortly after being accessed by potential injection sources

7. **Process Creation Anomalies** - Flag instances where system utilities like WerFault.exe are launched without typical error reporting context, especially when spawned by scripting engines
