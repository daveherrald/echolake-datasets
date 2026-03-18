# T1218.011-14: Rundll32 — Running DLL with .init extension and function

## Technique Context

T1218.011 involves using rundll32.exe, a legitimate Windows utility designed to execute DLL functions, for defense evasion purposes. Attackers commonly abuse rundll32 to proxy execution of malicious code while appearing as a legitimate Windows process. The detection community focuses on unusual rundll32 command lines, non-standard DLL paths, suspicious export functions, and files with non-standard extensions being loaded as DLLs. This specific test examines rundll32's ability to load a file with a `.init` extension (rather than `.dll`) and execute a function named `krnl`, demonstrating how attackers might use non-standard file extensions to evade detection rules that only monitor `.dll` files.

## What This Dataset Contains

The dataset captures a successful rundll32 execution with telemetry showing the complete process chain. Security event 4688 shows PowerShell (PID 27096) spawning cmd.exe with the command line `"cmd.exe" /c rundll32.exe C:\AtomicRedTeam\atomics\T1218.011\bin\_WT.init,krnl`, followed by rundll32.exe (PID 23476) being created with the command line `rundll32.exe  C:\AtomicRedTeam\atomics\T1218.011\bin\_WT.init,krnl`. Sysmon EID 1 events provide additional process creation details including file hashes, integrity levels, and parent-child relationships. The technique successfully executes as evidenced by normal exit codes (0x0) in Security 4689 events. Notably, the rundll32 process loads a file with the `.init` extension rather than the standard `.dll` extension, and attempts to call the `krnl` export function. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific content.

## What This Dataset Does Not Contain

The dataset lacks evidence of the actual DLL loading operation or the execution of the `krnl` function. There are no Sysmon EID 7 (Image Loaded) events showing the `_WT.init` file being loaded by rundll32, suggesting the file either doesn't exist, isn't a valid DLL, or doesn't export the specified function. The cmd.exe process exits with status 0x1 (failure), indicating the rundll32 operation was unsuccessful. The dataset doesn't capture any network connections, file modifications, or registry changes that might result from successful DLL execution, nor does it show Windows Defender blocking the operation (no ACCESS_DENIED exit codes observed).

## Assessment

This dataset provides good coverage for detecting rundll32 abuse through process creation monitoring but limited insight into actual DLL loading behavior. The Security 4688 and Sysmon EID 1 events effectively capture the suspicious command line pattern with a non-standard file extension, which is the primary detection opportunity for this technique variant. However, the unsuccessful execution means defenders cannot study the full attack chain or develop detection for post-execution behaviors. The data sources present (Security process auditing and Sysmon process creation) are sufficient for building detections around rundll32 command line abuse, particularly for non-standard file extensions.

## Detection Opportunities Present in This Data

1. **Rundll32 with non-standard file extension** - Security 4688 and Sysmon EID 1 show rundll32.exe loading a file with `.init` extension instead of `.dll`

2. **Rundll32 command line with suspicious export function** - Process creation events show rundll32 attempting to call function `krnl`, which could indicate malicious naming conventions

3. **Rundll32 loading from non-system paths** - Command line shows rundll32 accessing `C:\AtomicRedTeam\atomics\T1218.011\bin\_WT.init` from a non-standard location

4. **Process chain analysis** - Parent-child relationship showing PowerShell → cmd.exe → rundll32.exe execution chain typical of scripted attacks

5. **Failed rundll32 execution** - cmd.exe exit status 0x1 combined with rundll32 process creation could indicate attempted but failed DLL proxy execution

6. **Rundll32 spawned from command shell** - Unusual for legitimate rundll32 usage to be invoked via cmd.exe /c rather than directly
