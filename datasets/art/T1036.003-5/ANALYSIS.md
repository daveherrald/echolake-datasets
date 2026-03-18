# T1036.003-5: Rename Legitimate Utilities — Masquerading - powershell.exe running as taskhostw.exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) is a defense evasion technique where attackers rename legitimate system binaries to masquerade as other processes, often to evade process-based detections or blend in with expected system activity. This specific test demonstrates copying powershell.exe to taskhostw.exe in the user's AppData directory and executing it. The legitimate taskhostw.exe (Task Host Window) is a common Windows system process, making it an attractive masquerading target. Detection teams typically focus on identifying processes running from unusual locations, executable name mismatches with original filenames, or behavioral inconsistencies between expected and actual process capabilities.

## What This Dataset Contains

The dataset captures a complete masquerading execution sequence. Security event 4688 shows the initial PowerShell process creating cmd.exe with the command line `"cmd.exe" /c copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y & cmd.exe /K %APPDATA%\taskhostw.exe`, which copies PowerShell and immediately executes the renamed binary. The file copy operation is captured in Sysmon event 11 creating `C:\Windows\System32\config\systemprofile\AppData\Roaming\taskhostw.exe`. Most critically, Sysmon event 1 captures the masqueraded process creation showing `Image: C:\Windows\System32\config\systemprofile\AppData\Roaming\taskhostw.exe` with `OriginalFileName: PowerShell.EXE`, revealing the mismatch. The renamed PowerShell loads standard .NET runtime DLLs and PowerShell automation components, and creates a named pipe `\PSHost.134178971466232223.2108.DefaultAppDomain.taskhostw` that clearly indicates PowerShell functionality despite the process name. Windows Defender scanning activity is visible through process access events targeting MsMpEng.exe. The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no malicious script content.

## What This Dataset Does Not Contain

The dataset lacks network connections, registry modifications, or file system persistence beyond the single copied executable. There are no Sysmon ProcessCreate events for the initial cmd.exe processes due to the sysmon-modular configuration's include-mode filtering, which doesn't consider basic cmd.exe usage as suspicious. The technique generates no authentication events, privilege escalation attempts, or lateral movement indicators. PowerShell script block logging captures no meaningful attack content, only test framework preparation. The dataset doesn't show the cleanup phase where the copied binary would typically be deleted.

## Assessment

This dataset provides excellent detection opportunities for T1036.003 masquerading techniques. The combination of Security 4688 events with full command lines and Sysmon ProcessCreate events creates a comprehensive view of the attack chain. The key strength lies in Sysmon's OriginalFileName field, which definitively identifies the mismatch between the executed process name (taskhostw.exe) and the actual binary type (PowerShell.EXE). The file creation events, process behavioral artifacts (PowerShell DLL loads, named pipe creation patterns), and the complete command line showing the copy operation provide multiple detection vectors. This dataset would be highly valuable for testing and tuning masquerading detection rules.

## Detection Opportunities Present in This Data

1. **OriginalFileName Mismatch Detection** - Sysmon EID 1 ProcessCreate events where the Image filename differs from OriginalFileName field (taskhostw.exe vs PowerShell.EXE)

2. **Suspicious File Copy Operations** - Security EID 4688 showing cmd.exe copying PowerShell executable to user directories with rename operations in command lines

3. **Executable Creation in User Directories** - Sysmon EID 11 FileCreate events showing .exe files being created in AppData\Roaming locations

4. **PowerShell DLL Loading from Renamed Process** - Sysmon EID 7 ImageLoad events showing System.Management.Automation.dll loaded by processes not named powershell.exe

5. **PowerShell Named Pipe Patterns from Non-PowerShell Processes** - Sysmon EID 17 PipeEvent showing PSHost named pipes created by processes with names other than powershell.exe

6. **Process Behavioral Inconsistencies** - Correlation of process name (taskhostw.exe) with PowerShell-specific artifacts like .NET CLR loading and AMSI.dll loading patterns

7. **Suspicious Process Location Execution** - Security EID 4688 showing system utilities executing from non-standard locations like user profile directories
