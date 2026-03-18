# T1219-8: Remote Access Tools — NetSupport - RAT Execution

## Technique Context

T1219 (Remote Access Tools) represents adversary use of legitimate remote access and remote administration tools to establish persistent command and control channels. NetSupport Manager is a popular commercial remote administration tool that has been frequently abused by threat actors for malicious purposes. Unlike purpose-built malware, legitimate RATs like NetSupport present detection challenges because they use authorized protocols and often have valid code signatures. The detection community typically focuses on identifying suspicious installation methods (like silent installs with `/S /v/qn` flags), unusual execution contexts (like PowerShell-initiated deployments), and behavioral indicators of unauthorized remote access sessions.

## What This Dataset Contains

This dataset captures a failed attempt to execute the NetSupport RAT installer through PowerShell. The core evidence appears in Security EID 4688 showing the PowerShell command line: `"powershell.exe" & {Start-Process \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1219_NetSupport.exe\" -ArgumentList \"/S /v/qn\"}`. This reveals the silent installation attempt using MSI silent install flags (`/S /v/qn`).

The PowerShell channel (EID 4104) contains the scriptblock showing the Start-Process command: `& {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1219_NetSupport.exe" -ArgumentList "/S /v/qn"}`. Critically, PowerShell EID 4100 shows the failure: "Error Message = This command cannot be run due to the error: The system cannot find the file specified."

Sysmon captures extensive telemetry around PowerShell process creation and execution, including multiple PowerShell processes (PIDs 19288, 30928, 35348, 17184) and their associated .NET runtime loading (EID 7 events). The dataset includes process access events (Sysmon EID 10) showing inter-process communication between PowerShell instances and spawned processes like whoami.exe.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful NetSupport installation or execution because the target executable `T1219_NetSupport.exe` was not present at the expected path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1219_NetSupport.exe`. This means there are no network connections, registry modifications, service installations, or file system changes that would typically accompany a successful RAT deployment.

The Sysmon ProcessCreate events are limited to processes matching the sysmon-modular include rules (PowerShell, whoami), so any processes that might have been spawned by a successful NetSupport installation wouldn't appear unless they matched suspicious patterns. There are no Windows Defender alert events, indicating the endpoint protection system didn't detect any actual malicious behavior beyond the failed file execution attempt.

## Assessment

This dataset provides valuable telemetry for detecting RAT deployment attempts even when they fail. The PowerShell script block logging captures the exact command syntax used for silent RAT installation, while Security event logging provides command-line visibility with process lineage. The combination of failed execution error messages and suspicious command-line parameters creates a strong detection signature.

The data quality is excellent for building detections around PowerShell-based RAT deployment attempts, particularly focusing on the Start-Process cmdlet with silent installation flags. However, the dataset's utility is limited for understanding successful RAT behavior, post-installation persistence mechanisms, or network communication patterns.

## Detection Opportunities Present in This Data

1. **PowerShell Start-Process with Silent Install Flags**: PowerShell EID 4104 scriptblock containing `Start-Process` with arguments matching `/S /v/qn` or similar MSI silent install patterns

2. **RAT Installation Command Lines**: Security EID 4688 process creation events with command lines containing known RAT executables combined with silent installation parameters

3. **PowerShell Error Messages for Missing RAT Files**: PowerShell EID 4100 error events with messages "system cannot find the file specified" when targeting paths containing RAT-related filenames

4. **Nested PowerShell Execution Patterns**: Multiple PowerShell process creations in rapid succession (evident from Sysmon EID 1 events showing parent-child PowerShell relationships)

5. **Process Access to Short-Lived Processes**: Sysmon EID 10 events showing PowerShell processes accessing newly created processes like whoami.exe, indicating potential system reconnaissance

6. **Suspicious PowerShell Module Loading**: Sysmon EID 7 events showing System.Management.Automation.dll loading in PowerShell processes executing RAT deployment commands
