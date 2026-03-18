# T1055-13: Process Injection — UUID custom process Injection

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where attackers inject malicious code into legitimate processes to evade detection, access higher privileges, or persist in memory without creating new processes. The "UUID custom process injection" variant refers to using UUIDs (Universally Unique Identifiers) to obfuscate shellcode within process memory — a technique that leverages the Windows RPC UUID string parsing functionality to convert UUID strings into binary shellcode for execution.

The detection community focuses heavily on process access events (particularly with high-privilege access rights), cross-process memory operations, and unusual parent-child process relationships. Modern EDR solutions monitor for processes accessing other processes with rights like PROCESS_ALL_ACCESS (0x1FFFFF), unusual DLL loads, and injection-related API calls through call stack analysis.

## What This Dataset Contains

This dataset captures a failed attempt at UUID-based process injection. The PowerShell test framework attempted to execute `C:\AtomicRedTeam\atomics\T1055\bin\x64\uuid_injection.exe` but failed with a "file not found" error (PowerShell EID 4100: "The system cannot find the file specified").

Key observable events include:
- PowerShell process creation with the injection command line: `"powershell.exe" & {Start-Process \"C:\AtomicRedTeam\atomics\T1055\bin\x64\uuid_injection.exe\" Start-Sleep -Seconds 7 Get-Process -Name Notepad -ErrorAction SilentlyContinue | Stop-Process -Force}` (Security EID 4688)
- Two suspicious Sysmon EID 10 (Process Access) events showing PowerShell accessing both `whoami.exe` (PID 16928) and another PowerShell process (PID 17228) with maximum access rights (GrantedAccess: 0x1FFFFF)
- Call traces in the process access events showing .NET System assembly involvement: `C:\Windows\assembly\NativeImages_v4.0.30319_64\System\22f4d83e48c2201947e262d4bca638b9\System.ni.dll`
- Multiple PowerShell process creations suggesting script block execution attempts
- Standard .NET runtime DLL loads (mscoree.dll, mscoreei.dll, clr.dll) across multiple PowerShell processes

## What This Dataset Does Not Contain

The dataset lacks the actual injection behavior because the uuid_injection.exe binary was missing from the test environment. Consequently, we see no:
- Successful process injection telemetry (memory writes, thread creation in target processes)
- Target process (Notepad) creation or manipulation
- Shellcode execution artifacts
- Network connections or file system modifications typical of successful payload execution
- Cross-process thread creation events (Sysmon EID 8)

The Sysmon ProcessCreate events are limited due to the sysmon-modular include-mode filtering, which only captured the `whoami.exe` execution but not the attempted uuid_injection.exe launch.

## Assessment

This dataset provides excellent examples of process access detection opportunities despite the failed injection attempt. The Sysmon EID 10 events with 0x1FFFFF access rights and detailed call traces offer high-fidelity indicators of attempted process manipulation. The PowerShell script block logging (EID 4104) clearly shows the injection attempt, while Security EID 4688 events provide complete command-line visibility.

However, the missing binary significantly limits the dataset's value for understanding successful UUID injection techniques. The telemetry represents preparation and attempt phases rather than execution phases, making it more valuable for detecting injection setup rather than injection success.

## Detection Opportunities Present in This Data

1. **High-privilege process access patterns** - Sysmon EID 10 events showing GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS) from PowerShell to other processes, especially with .NET assembly call traces
2. **Suspicious PowerShell command lines** - Security EID 4688 showing Start-Process commands targeting non-standard executable paths like `C:\AtomicRedTeam\atomics\T1055\bin\x64\uuid_injection.exe`
3. **PowerShell script block injection indicators** - EID 4104 events containing process injection-related cmdlets combined with Start-Process and target process manipulation
4. **Cross-process access from scripting engines** - PowerShell processes accessing other processes with full access rights, particularly when combined with .NET runtime call stacks
5. **Failed execution followed by process enumeration** - PowerShell errors (EID 4100) for missing injection tools followed by Get-Process cmdlets, indicating reconnaissance after failed injection attempts
6. **Multiple PowerShell process spawning** - Rapid creation of PowerShell child processes suggesting script-based process manipulation attempts
