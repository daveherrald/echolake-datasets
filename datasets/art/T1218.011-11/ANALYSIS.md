# T1218.011-11: Rundll32 — Rundll32 with Ordinal Value

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows utility rundll32.exe to execute malicious code. Rundll32.exe is designed to load and run 32-bit DLLs, making it an attractive target for adversaries seeking to proxy execution through a signed Microsoft binary. This specific test (T1218.011-11) demonstrates execution using an ordinal value (`#2`) instead of a function name, which is a common obfuscation technique. The detection community focuses on unusual DLL paths, suspicious command-line patterns with ordinals, unsigned DLLs, and process chains involving rundll32.exe spawning from unexpected parents.

## What This Dataset Contains

This dataset captures a successful rundll32.exe execution with ordinal value. The process chain shows:
- PowerShell (PID 31520) executing: `powershell.exe`
- CMD (PID 32188) executing: `"cmd.exe" /c rundll32.exe "C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx64.dll",#2`
- Rundll32 (PID 29904) executing: `rundll32.exe  "C:\AtomicRedTeam\atomics\T1218.010\bin\AllTheThingsx64.dll",#2`

Key telemetry includes:
- **Sysmon Event 1**: Process creation for cmd.exe, rundll32.exe, and whoami.exe with full command lines
- **Security Event 4688**: Process creation events with identical command-line details
- **Security Event 4689**: Process termination events showing rundll32.exe exited with status 0xFFFFFFFF (-1), indicating failure
- **Sysmon Event 10**: Process access events showing PowerShell accessing child processes
- **PowerShell Events 4103/4104**: Standard test framework activity (Set-ExecutionPolicy, CIM aliases)

The rundll32.exe process attempts to load `AllTheThingsx64.dll` using ordinal `#2` but appears to fail based on the exit status.

## What This Dataset Does Not Contain

The dataset lacks several key elements for comprehensive rundll32 analysis:
- **DLL load events**: No Sysmon Event 7 (Image Loaded) for the target DLL, suggesting it failed to load or was blocked
- **File access events**: Missing Sysmon Event 11 for DLL file access attempts
- **Network activity**: No DNS queries or network connections from rundll32.exe
- **Registry modifications**: No evidence of registry changes that might indicate successful DLL execution
- **Success telemetry**: The exit code 0xFFFFFFFF suggests the technique failed, possibly due to Windows Defender intervention

The sysmon-modular configuration's include-mode filtering captured rundll32.exe (as it's a known LOLBin) but may have missed other processes if they didn't match suspicious patterns.

## Assessment

This dataset provides good coverage of the initial execution attempt but limited insight into the failure mode. The Security 4688 events offer complete command-line visibility, while Sysmon Event 1 captures the process creation with detailed metadata including hashes and parent-child relationships. The process access events (Sysmon 10) show PowerShell's interaction with spawned processes, which could be valuable for detecting automation frameworks. However, the apparent execution failure limits the dataset's utility for understanding successful rundll32 abuse patterns. The telemetry is most valuable for detecting the attempt rather than analyzing post-execution behavior.

## Detection Opportunities Present in This Data

1. **Rundll32 ordinal execution detection**: Monitor Security 4688/Sysmon 1 for rundll32.exe with ordinal syntax (`#[0-9]+`) in command line
2. **Suspicious DLL path detection**: Alert on rundll32.exe loading DLLs from non-standard paths like `C:\AtomicRedTeam\` or user-writable directories
3. **PowerShell-to-rundll32 process chain**: Detect PowerShell spawning cmd.exe that subsequently launches rundll32.exe
4. **Rundll32 execution failure monitoring**: Track rundll32.exe processes with exit codes indicating failure (0xFFFFFFFF) as potential blocked attacks
5. **Cross-process access from PowerShell**: Monitor Sysmon 10 events for PowerShell accessing rundll32.exe processes with high privileges (0x1F3FFF)
6. **Atomic Red Team artifact detection**: Baseline for paths containing `AtomicRedTeam` or `atomics` in command lines as testing activity
7. **CMD proxy execution detection**: Monitor for cmd.exe with `/c` parameter launching rundll32.exe as potential process injection chain
