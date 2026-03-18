# T1106-5: Native API — Run Shellcode via Syscall in Go

## Technique Context

T1106 Native API covers adversary use of Windows APIs to execute code, particularly bypassing or evading security controls. This specific test (T1106-5) demonstrates shellcode execution via direct system calls implemented in Go. Direct syscalls represent an advanced evasion technique where attackers bypass user-mode API hooks by calling directly into the kernel (ntdll.dll), avoiding EDR monitoring that typically intercepts higher-level Win32 API calls. This technique has grown in popularity among modern malware families and penetration testing tools because it can circumvent many behavioral detection mechanisms that rely on API hooking.

The detection community focuses on identifying unusual patterns in process behavior, memory allocation patterns, and the presence of shellcode injection techniques when monitoring for T1106 abuse.

## What This Dataset Contains

The dataset captures a PowerShell execution chain that launches a custom Go-compiled binary (`syscall.exe`) designed to demonstrate direct syscall usage. The telemetry shows:

**Process Chain Evidence (Security/Sysmon EID 1):**
- Parent PowerShell (PID 20828) executing `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe -debug}`
- Child PowerShell (PID 35156) spawned to execute the syscall binary
- `whoami.exe` execution (PID 20756) for system discovery

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing whoami.exe with full access rights (0x1FFFFF)
- PowerShell accessing the child PowerShell process with full access rights
- Both events tagged with "Dynamic-link Library Injection" detection rules

**Image Load Events (Sysmon EID 7):**
- Standard .NET Framework loading (mscoree.dll, mscoreei.dll, clr.dll)
- PowerShell automation assembly loading
- Windows Defender integration (MpOAV.dll, MpClient.dll) suggesting real-time scanning

**PowerShell Script Block Logging (EID 4104):**
- Command line showing syscall.exe execution: `& {C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe -debug}`
- Standard PowerShell test framework boilerplate (Set-StrictMode, execution policy bypass)

## What This Dataset Does Not Contain

Critically, **this dataset lacks the actual syscall.exe process creation and execution telemetry**. There are no Sysmon EID 1 events showing the Go binary launching, no image loads from the syscall.exe process, and no memory allocation or injection events that would typically accompany shellcode execution techniques. This suggests either:

1. Windows Defender blocked the syscall.exe execution before it could start
2. The sysmon-modular configuration filtered out the process creation (though custom binaries should trigger include rules)
3. The syscall.exe binary failed to execute properly

The absence of network connections, file writes from syscall.exe, or memory manipulation events indicates the core technique demonstration was not captured in the telemetry. We also see no Windows Defender alert events or process termination with access-denied exit codes that would confirm active blocking.

## Assessment

This dataset provides limited value for T1106 detection engineering because the actual native API/syscall technique execution is absent from the telemetry. While it captures the PowerShell delivery mechanism and some related process interactions, the core syscall-based shellcode execution that defines this technique is not represented in the collected events.

The dataset is more useful for understanding PowerShell-based execution chains and process monitoring patterns than for developing detections specific to direct syscall usage or shellcode injection via native APIs.

## Detection Opportunities Present in This Data

1. **PowerShell execution of suspicious binaries from AtomicRedTeam directories** - Security EID 4688 command line contains `C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe`

2. **PowerShell script block logging of syscall binary execution** - PowerShell EID 4104 captures the exact command: `& {C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe -debug}`

3. **Unusual process access patterns** - Sysmon EID 10 shows PowerShell accessing other processes with full access rights (0x1FFFFF), which could indicate injection attempts

4. **PowerShell spawning child PowerShell processes** - Process tree analysis showing powershell.exe -> powershell.exe chains for execution

5. **Discovery tool execution from PowerShell** - whoami.exe launched from PowerShell context, indicating potential system reconnaissance

6. **Binary execution from test/research directories** - File path analysis for executables in AtomicRedTeam, testing, or research-related directories
