# T1218.007-9: Msiexec — Msiexec.exe - Execute the DllRegisterServer function of a DLL

## Technique Context

T1218.007 represents the abuse of msiexec.exe, Windows' legitimate Microsoft Installer service, as a defense evasion technique. Attackers leverage msiexec.exe's trusted status and various command-line switches to execute malicious code while appearing as a legitimate system process. The `/y` flag specifically calls the DllRegisterServer function of a specified DLL, effectively allowing arbitrary DLL execution through a signed Microsoft binary.

This technique is particularly valuable to attackers because msiexec.exe is a trusted, signed binary that's commonly whitelisted in application control solutions. The detection community focuses on unusual command-line arguments to msiexec.exe, particularly the `/y` switch combined with suspicious DLL paths, process ancestry chains that deviate from normal software installation workflows, and child processes spawned by msiexec.exe that indicate code execution.

## What This Dataset Contains

This dataset captures a successful execution of msiexec.exe with the `/y` flag to execute a DLL's DllRegisterServer function. The core process chain is:

- PowerShell (PID 37356) spawns cmd.exe with command `"cmd.exe" /c c:\windows\system32\msiexec.exe /y "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"`
- cmd.exe (PID 26696) spawns msiexec.exe with command `c:\windows\system32\msiexec.exe /y "C:\AtomicRedTeam\atomics\T1218.007\bin\MSIRunner.dll"`
- msiexec.exe (PID 13288) spawns PowerShell (PID 35116) with command `powershell.exe -nop -Command Write-Host DllRegisterServer export executed me; exit`

Security events 4688 capture all process creations with full command lines. Sysmon events include ProcessCreate (EID 1) for the key processes due to the sysmon-modular config's include rules matching msiexec.exe, cmd.exe, whoami.exe, and PowerShell. PowerShell script block logging (EID 4104) captures the executed command `Write-Host DllRegisterServer export executed me; exit`, demonstrating successful DLL function execution.

The technique execution is fully successful—all processes exit with status 0x0, and the PowerShell command executes as intended, proving the DLL's DllRegisterServer function was called and able to spawn a child process.

## What This Dataset Does Not Contain

The dataset lacks some events that could provide additional context. Notably, there's no Sysmon file creation event for the MSIRunner.dll itself, suggesting it was pre-positioned before the dataset collection window. The test DLL appears to be a simple proof-of-concept that spawns PowerShell rather than performing more sophisticated malicious actions like network communication, file manipulation, or persistence mechanisms.

Windows Defender was active during execution but did not block this technique, as evidenced by the successful completion and normal exit codes. The PowerShell channel contains mostly test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual malicious command execution, which is captured in the Security channel's process creation events instead.

## Assessment

This dataset provides excellent telemetry for detecting T1218.007 abuse. The combination of Security 4688 events with command-line auditing and Sysmon ProcessCreate events creates multiple detection opportunities. The process ancestry chain is clearly visible, showing the unusual parent-child relationship of msiexec.exe spawning PowerShell. The command-line arguments are fully captured, including the suspicious `/y` flag and the path to a DLL in a non-standard location.

The dataset would be stronger with additional context around the DLL file itself (creation time, hash values, digital signature status) and any registry modifications that might occur during DLL registration. However, for detection engineering focused on process-based analytics, this dataset provides robust coverage.

## Detection Opportunities Present in This Data

1. **Msiexec.exe with /y parameter**: Detect msiexec.exe execution with the `/y` command-line flag, especially when the target DLL path is outside standard Windows or Program Files directories.

2. **Unusual msiexec.exe parent processes**: Alert on msiexec.exe spawned by cmd.exe or PowerShell rather than typical software installation processes or Windows Installer service.

3. **Child processes from msiexec.exe**: Monitor for msiexec.exe spawning unexpected child processes like PowerShell, cmd.exe, or other executables that indicate code execution rather than normal installation activities.

4. **Suspicious DLL paths in msiexec.exe commands**: Flag DLL paths in temporary directories, user profiles, or unusual filesystem locations being referenced by msiexec.exe `/y` operations.

5. **Process ancestry chain anomalies**: Detect the specific chain of PowerShell > cmd.exe > msiexec.exe > PowerShell, which is unusual for legitimate software installation workflows.

6. **Msiexec.exe execution with non-standard working directories**: Alert when msiexec.exe runs from directories other than System32 or typical installation paths, as seen with the CurrentDirectory of C:\Windows\Temp\.
