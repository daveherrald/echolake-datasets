# T1137.006-4: Add-ins — Persistent Code Execution Via Excel VBA Add-in File (XLAM)

## Technique Context

T1137.006 focuses on establishing persistence through Microsoft Office add-ins, specifically targeting Excel VBA add-in files (.xlam). Attackers use this technique to maintain access by placing malicious add-ins in locations where Excel automatically loads them at startup, such as the XLSTART directory. This provides a stealthy persistence mechanism that activates whenever the user opens Excel, potentially executing arbitrary VBA code without explicit user interaction.

The detection community typically focuses on monitoring file writes to Office add-in directories, process spawning from Office applications, and PowerShell script execution that manipulates add-in files. This technique is particularly concerning because it leverages trusted Office functionality and may evade basic application whitelisting controls.

## What This Dataset Contains

This dataset captures a failed attempt to implement Excel VBA add-in persistence. The key events show:

**PowerShell Script Execution**: Security event 4688 shows the main PowerShell command: `"powershell.exe" & {Copy \"C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\ExcelVBAaddin.xlam\" \"$env:APPDATA\Microsoft\Excel\XLSTART\notepad.xlam\" Start-Process \"Excel\"}`

**Failed File Copy Operation**: PowerShell events 4100 and 4102 document the failure: "Could not find a part of the path 'C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Excel\XLSTART\notepad.xlam'" indicating the target directory structure doesn't exist.

**Failed Excel Launch**: PowerShell event 4100 shows: "This command cannot be run due to the error: The system cannot find the file specified" when attempting to start Excel, suggesting Excel is not installed on this system.

**Process Creation Chain**: Sysmon events 1 capture the process hierarchy with PowerShell spawning child PowerShell processes and a whoami.exe execution for system discovery.

**Windows Defender Integration**: Multiple Sysmon events 7 show MpOAV.dll and MpClient.dll loading into PowerShell processes, indicating active real-time protection scanning.

## What This Dataset Does Not Contain

The dataset lacks successful technique execution telemetry because the attack failed at multiple stages. Missing elements include:

- No Sysmon event 11 showing successful .xlam file creation in the XLSTART directory
- No Excel process creation or related Office application telemetry
- No file system events showing the malicious add-in being accessed or executed
- No registry modifications related to Office add-in configuration
- No network connections that might result from successful add-in execution

The failure appears to stem from the test running under the SYSTEM account in an environment without Excel installed and without the necessary directory structure for user-specific Office add-ins.

## Assessment

This dataset provides limited value for detection engineering of successful T1137.006 attacks but offers excellent insight into failed attack attempts and the associated error patterns. The PowerShell command-line artifacts and script block logging demonstrate how attackers structure these operations, while the error messages reveal environmental dependencies.

For building detections of this technique, you would need successful execution data showing actual .xlam file creation in XLSTART directories, Excel process behavior, and potentially VBA execution telemetry. However, the command-line patterns and PowerShell artifacts shown here could help detect attempted attacks even when they fail.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection**: Monitor Security event 4688 for command lines containing paths to XLSTART directories and .xlam file operations, specifically patterns like `Copy *\.xlam *XLSTART*`

2. **PowerShell Script Block Monitoring**: Detect PowerShell event 4104 script blocks containing Office add-in manipulation commands, particularly Copy-Item operations targeting Excel add-in directories

3. **Failed Office Operations**: Monitor PowerShell error events (4100, 4102) for failures related to Office directory paths and Excel startup attempts, which may indicate reconnaissance or failed persistence attempts

4. **Process Creation Anomalies**: Alert on PowerShell spawning from unexpected parent processes when combined with Office-related command line arguments

5. **File Path Enumeration**: Watch for process access to Office application directories and XLSTART paths, even when operations fail, as indicators of technique research or preparation

6. **System Discovery Correlation**: Correlate whoami.exe execution (Sysmon event 1) with subsequent Office-related PowerShell operations as potential attack chain indicators
