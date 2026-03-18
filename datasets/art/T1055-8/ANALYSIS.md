# T1055-8: Process Injection — Remote Process Injection with Go using RtlCreateUserThread WinAPI

## Technique Context

Process injection is a fundamental technique used by attackers to execute malicious code within the address space of legitimate processes, helping evade detection and inherit the privileges and security context of the target process. T1055-8 specifically covers remote process injection using the RtlCreateUserThread Windows API, which is a lower-level alternative to the more commonly monitored CreateRemoteThread API. Attackers favor RtlCreateUserThread because it's less commonly monitored by security tools and provides similar functionality for creating threads in remote processes.

The detection community focuses on monitoring process access events with high-privilege access rights (like PROCESS_VM_WRITE and PROCESS_CREATE_THREAD), unusual cross-process activity patterns, and the loading of suspicious DLLs or execution of shellcode in processes that shouldn't normally contain such code. RtlCreateUserThread injection typically involves opening a handle to a target process, allocating memory, writing shellcode, and creating a remote thread to execute it.

## What This Dataset Contains

This dataset captures a Go-based process injection test that uses RtlCreateUserThread to inject into both `whoami.exe` and `werfault.exe` processes. The key events show the complete injection lifecycle:

**PowerShell Test framework Activity:**
- Security 4688 shows PowerShell launching with command line `"powershell.exe" & {$process = Start-Process C:\Windows\System32\werfault.exe -passthru; C:\AtomicRedTeam\atomics\T1055\bin\x64\RtlCreateUserThread.exe -pid $process.Id -debug}`
- PowerShell 4104 script blocks capture the injection command: `C:\AtomicRedTeam\atomics\T1055\bin\x64\RtlCreateUserThread.exe -pid $process.Id -debug`

**Process Creation Chain:**
- Sysmon EID 1 captures `whoami.exe` creation (PID 9124) by PowerShell
- Sysmon EID 1 captures `werfault.exe` creation (PID 10816) as the target injection process
- Security 4688 events provide full command-line visibility for both processes

**Process Access Events:**
- Sysmon EID 10 shows PowerShell (PID 10432) accessing `whoami.exe` (PID 9124) with GrantedAccess `0x1FFFFF` (PROCESS_ALL_ACCESS)
- Sysmon EID 10 shows PowerShell accessing another PowerShell process (PID 39804) with the same high privileges
- CallTrace fields show the .NET call stack leading to the process access

**Image Loads:**
- Multiple Sysmon EID 7 events show .NET runtime DLLs (mscoree.dll, mscoreei.dll, clr.dll) loading in PowerShell processes, indicating .NET execution environment setup
- Windows Defender DLLs (MpOAV.dll, MpClient.dll) load, showing active endpoint protection monitoring

## What This Dataset Does Not Contain

The dataset lacks critical telemetry that would normally be present in a successful process injection:

**Missing RtlCreateUserThread Binary Execution:** The Sysmon ProcessCreate events don't capture the actual `RtlCreateUserThread.exe` binary execution, likely due to the sysmon-modular include-mode filtering that only captures known-suspicious process patterns. This is a significant gap since the injection payload execution isn't visible.

**No Thread Creation Events:** Sysmon doesn't provide native thread creation monitoring, so the actual RtlCreateUserThread API calls that create remote threads in target processes aren't captured.

**Limited Memory Allocation Visibility:** There are no events showing VirtualAllocEx or WriteProcessMemory calls that would typically precede thread creation in process injection scenarios.

**Missing Injection Artifacts:** No evidence of shellcode execution, DLL injection, or behavior changes in the target processes that would indicate successful injection.

**Incomplete Process Access Context:** While process access events show high privileges being requested, there's no indication of what operations were actually performed with those privileges.

## Assessment

This dataset provides partial visibility into the process injection attempt but lacks the most critical evidence of successful injection. The PowerShell script blocks clearly show the injection intent and command structure, and the process access events with PROCESS_ALL_ACCESS privileges are strong indicators of injection attempts. However, the absence of the actual injection binary execution and thread creation events significantly limits the dataset's value for understanding the complete attack lifecycle.

The data sources captured here are better suited for detecting injection attempts rather than successful injections. The high-privilege process access events are valuable detection opportunities, but the lack of thread creation and memory operation visibility means defenders would need additional telemetry sources to confirm successful injection and understand the post-injection behavior.

## Detection Opportunities Present in This Data

1. **High-Privilege Cross-Process Access** - Monitor Sysmon EID 10 events where GrantedAccess contains 0x1FFFFF or other high-privilege access masks (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD) between unrelated processes

2. **PowerShell Process Injection Commands** - Detect PowerShell 4104 script blocks containing process injection tools like "RtlCreateUserThread.exe" or similar injection utilities with PID parameters

3. **Suspicious Process Access Patterns** - Alert on process access events where PowerShell or other scripting engines access legitimate Windows binaries (whoami.exe, werfault.exe) with full access rights

4. **Process Creation with Injection Context** - Correlate Security 4688 process creation events showing PowerShell launching with command lines containing injection tools and target process spawning

5. **Scripting Engine Cross-Process Activity** - Monitor for PowerShell processes accessing other processes with high privileges, especially when combined with external binary execution patterns

6. **Process Spawning for Injection Targets** - Detect patterns where a process spawns a target process (like werfault.exe) followed immediately by high-privilege access attempts, indicating potential hollow process injection
