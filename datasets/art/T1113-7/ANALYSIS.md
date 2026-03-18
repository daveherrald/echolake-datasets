# T1113-7: Screen Capture — Screen Capture (Windows Screencapture) on Windows 11 Enterprise domain workstation

## Technique Context

T1113 (Screen Capture) involves adversaries taking screenshots of victims' screens to gather information displayed at the time, including credentials, sensitive documents, or system information. This technique is commonly used during collection phases of attacks for reconnaissance or credential harvesting. The Windows Problem Steps Recorder (PSR.exe) is a legitimate Microsoft tool that can capture screen activity and save it as compressed files, making it an attractive LOLBin for attackers. Detection engineers typically focus on monitoring PSR.exe execution with suspicious parameters, file creation in unusual locations, and the capture of screen content without user interaction.

## What This Dataset Contains

This dataset captures a PowerShell-based screen capture attack using Windows PSR.exe. The primary evidence includes:

**Process Creation Chain**: Security 4688 events show powershell.exe (PID 45036) spawning a child powershell.exe (PID 15196) with the command line `"powershell.exe" & {cmd /c start /b psr.exe /start /output c:\temp\T1113_desktop.zip /sc 1 /gui 0 /stopevent 12` followed by cmd.exe (PID 14472) and ultimately psr.exe (PID 16480) with parameters `/start /output c:\temp\T1113_desktop.zip /sc 1 /gui 0 /stopevent 12`.

**PSR.exe Execution**: Security events show psr.exe being launched twice with identical command lines, both processes exiting with status `0xC000042C` (STATUS_PROCESS_IN_JOB), indicating the processes were terminated.

**PowerShell Script Content**: PowerShell 4104 script block events capture the full attack script: `cmd /c start /b psr.exe /start /output c:\temp\T1113_desktop.zip /sc 1 /gui 0 /stopevent 12` followed by mouse event simulation via P/Invoke to user32.dll and a timeout command to stop PSR.

**Sysmon Process and Image Events**: Sysmon EID 1 events captured whoami.exe, powershell.exe, and cmd.exe creation but notably missing psr.exe process creation due to the include-mode filtering in sysmon-modular configuration.

## What This Dataset Does Not Contain

**PSR.exe Sysmon Events**: The sysmon-modular configuration's include-mode filtering for ProcessCreate (EID 1) did not capture psr.exe execution, as it's not in the known-suspicious process patterns. This is a significant gap for detecting this specific LOLBin usage.

**File Creation Events**: No Sysmon EID 11 events for the target output file `c:\temp\T1113_desktop.zip` are present, suggesting either the file wasn't created due to process termination or the Sysmon file monitoring rules didn't capture it.

**Network Activity**: No network connections from psr.exe are present, indicating this was purely local screen capture without exfiltration in this test.

**Successful Execution Artifacts**: Both psr.exe processes exited with error status `0xC000042C`, suggesting the screen capture may not have completed successfully.

## Assessment

This dataset provides moderate value for detection engineering focused on PowerShell-based screen capture attacks. The Security 4688 events with command-line logging provide complete visibility into the attack chain, including the specific PSR.exe parameters used. The PowerShell script block logging (4104) captures the full attack payload, making this excellent for PowerShell-based detection rules. However, the missing Sysmon ProcessCreate events for psr.exe significantly limit the dataset's utility for environments relying primarily on Sysmon for process monitoring. The apparent failure of the PSR.exe execution (based on exit codes) means this dataset shows attempt telemetry rather than successful screen capture, which is still valuable for detection but doesn't demonstrate post-exploitation artifacts.

## Detection Opportunities Present in This Data

1. **PSR.exe Command Line Parameters**: Security 4688 events showing psr.exe execution with `/start`, `/output`, `/gui 0`, and `/stopevent` parameters indicating automated screen recording
2. **PowerShell Script Block Analysis**: PowerShell 4104 events containing PSR.exe execution combined with user32.dll P/Invoke calls for mouse simulation
3. **Process Chain Analysis**: Parent-child relationships showing powershell.exe → cmd.exe → psr.exe execution chains
4. **PSR.exe with Suspicious Output Paths**: Command lines containing `/output` parameters pointing to temp directories or unusual file paths
5. **PowerShell Mouse Event Simulation**: Script blocks containing `[DllImport("user32.dll")]` and `mouse_event` function calls combined with screen capture tools
6. **PSR.exe Background Execution**: `/gui 0` parameter indicating hidden GUI execution of Problem Steps Recorder
7. **Automated PSR.exe Control**: PowerShell scripts containing both psr.exe start and stop commands with timeout operations
8. **Multiple PSR.exe Process Terminations**: Security 4689 events showing repeated psr.exe process exits with error codes
