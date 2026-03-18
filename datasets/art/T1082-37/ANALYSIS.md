# T1082-37: System Information Discovery — Identify System Locale and Regional Settings with PowerShell

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries gather information about the target system's configuration, hardware, software, and environment. This specific test focuses on locale and regional settings discovery using PowerShell's `Get-Culture` cmdlet. System locale information reveals the target's geographic location, language preferences, time zone settings, and cultural formatting conventions—valuable intelligence for targeted attacks, social engineering, or determining operational security measures. Detection teams typically monitor for discovery commands, unusual system information queries, and reconnaissance patterns that indicate an adversary is mapping their environment.

## What This Dataset Contains

This dataset captures a PowerShell-based system locale discovery operation with the following key events:

**Process Chain**: The attack follows a PowerShell → cmd.exe → PowerShell execution chain. Security Event 4688 shows the initial PowerShell process (PID 10492), spawning cmd.exe (PID 10116) with command line `"cmd.exe" /c powershell.exe -c "Get-Culture | Format-List | Out-File -FilePath %TMP%\a.txt"`, which then launches a second PowerShell instance (PID 35136) to execute the actual discovery command.

**Core Discovery Activity**: PowerShell Event 4103 captures the primary technique execution: `CommandInvocation(Get-Culture): "Get-Culture"` followed by `CommandInvocation(Format-List): "Format-List"` and `CommandInvocation(Out-File): "Out-File"` with parameter `name="FilePath"; value="C:\Windows\TEMP\a.txt"`. The script block logging (Event 4104) shows: `Get-Culture | Format-List | Out-File -FilePath C:\Windows\TEMP\a.txt`.

**File System Artifacts**: Sysmon Event 11 records the creation of the output file `C:\Windows\Temp\a.txt` by the PowerShell process (PID 35136), providing evidence of the reconnaissance data being written to disk.

**Process Relationships**: Sysmon Event 1 captures three key process creations—whoami.exe (PID 40912), cmd.exe (PID 10116), and the final PowerShell instance (PID 35136)—with complete command lines and parent-child relationships showing the execution flow.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide complete visibility into this technique:

**Output Content**: While we see the file creation event, the actual system locale data retrieved by `Get-Culture` is not captured in the logs, limiting analysis of what information was disclosed.

**Initial Process Creation**: The sysmon-modular configuration uses include-mode filtering for ProcessCreate events, so the first PowerShell process (PID 10492) creation is missing from Sysmon logs, though it's captured in Security Event 4688.

**Direct PowerShell Execution**: The technique uses an unnecessary cmd.exe wrapper around the PowerShell command, which may not represent typical adversary behavior that would execute PowerShell directly.

**Network Activity**: No network connections are captured, indicating this is pure local reconnaissance without data exfiltration attempts.

## Assessment

This dataset provides solid detection coverage for PowerShell-based system information discovery techniques. The combination of Security Event 4688 for complete process creation visibility, PowerShell Events 4103/4104 for cmdlet invocation and script block content, and Sysmon Event 11 for file artifacts creates multiple detection opportunities. The process chain telemetry is comprehensive, showing both the execution methodology and the specific discovery commands used. However, the artificial cmd.exe wrapper and missing output content somewhat limit its real-world applicability. The data quality is excellent for building detections around PowerShell discovery patterns, command-line analysis, and file-based output indicators.

## Detection Opportunities Present in This Data

1. **PowerShell Culture Discovery Commands**: Monitor PowerShell Events 4103 for `CommandInvocation(Get-Culture)` indicating system locale reconnaissance attempts.

2. **Discovery Command Patterns**: Detect PowerShell script blocks (Event 4104) containing `Get-Culture` combined with output redirection cmdlets like `Out-File` or `Format-List`.

3. **Reconnaissance Output Files**: Alert on Sysmon Event 11 file creation events where PowerShell processes create files in temp directories with suspicious naming patterns (single letter filenames like "a.txt").

4. **Process Chain Analysis**: Identify Security Event 4688 process creation sequences where PowerShell spawns cmd.exe which then spawns another PowerShell instance, indicating potential evasion or automation techniques.

5. **System Information Aggregation**: Correlate multiple system discovery commands (whoami.exe execution followed by Get-Culture) within short time windows to identify comprehensive reconnaissance activities.

6. **Temp Directory Surveillance**: Monitor file creation events in `%TEMP%` or `C:\Windows\Temp\` by PowerShell processes, particularly when combined with discovery-related parent processes or command lines.
