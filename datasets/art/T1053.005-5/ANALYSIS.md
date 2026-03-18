# T1053.005-5: Scheduled Task — Task Scheduler via VBA (Invoke-MalDoc)

## Technique Context

T1053.005 focuses on scheduled task creation for persistence, execution, and privilege escalation. Attackers commonly use this technique to maintain presence on compromised systems by creating tasks that execute malicious payloads at specific intervals or system events. This particular test attempts to simulate a malicious document scenario where VBA macro code creates a scheduled task.

The detection community typically monitors for suspicious scheduled task creation through multiple channels: Task Scheduler service logs, process creation events showing schtasks.exe or taskschd.dll usage, registry modifications under Task Scheduler keys, and PowerShell ScriptBlock logging when tasks are created programmatically. The VBA approach adds complexity by requiring Office applications to execute macro code, which would normally involve COM object instantiation and Office process spawning.

## What This Dataset Contains

This dataset captures a failed attempt to execute the Invoke-MalDoc technique. The key telemetry shows:

**PowerShell Script Block Evidence**: EID 4104 events contain the complete Invoke-MalDoc function definition and execution attempt. The script downloads `Invoke-MalDoc.ps1` from GitHub and attempts to execute with parameters `-macroFile "C:\AtomicRedTeam\atomics\T1053.005\src\T1053.005-macrocode.txt" -officeProduct "Word" -sub "Scheduler"`.

**Critical Failure Point**: PowerShell EID 4100 shows "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered (Exception from HRESULT: 0x80040154 (REGDB_E_CLASSNOTREG))". This indicates Microsoft Word COM objects are not available.

**Process Chain**: Security EID 4688 events show the process execution chain: initial powershell.exe (PID 0x10b0) spawns whoami.exe (PID 0x1958) and a second powershell.exe (PID 0x1678) with the full Invoke-MalDoc command line.

**Network Activity**: Sysmon EID 3 events show Windows Defender making outbound HTTPS connections to 172.178.160.20:443, and EID 22 shows DNS resolution for raw.githubusercontent.com, indicating the script successfully downloaded the Invoke-MalDoc payload.

## What This Dataset Does Not Contain

**No Office Application Processes**: The dataset lacks any evidence of Microsoft Word process creation, which should occur when `New-Object -ComObject "Word.Application"` executes successfully. The COM registration error prevents Word from launching.

**No Scheduled Task Creation**: Since the VBA macro never executes due to the Office COM failure, there are no Task Scheduler-related events (no schtasks.exe processes, no Task Scheduler service logs, no registry modifications under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache).

**No VBA Execution Telemetry**: The failure to instantiate Word means no VBA runtime events, no macro security prompts, and no execution of the actual scheduled task creation code contained in the macro file.

**No Task Scheduler Service Interaction**: The Windows Task Scheduler service never receives requests to create tasks, so logging from Microsoft-Windows-TaskScheduler/Operational channel would be absent.

## Assessment

This dataset provides limited value for detecting successful T1053.005 scheduled task creation via VBA macros, as the technique fails at the COM object instantiation stage. However, it offers valuable telemetry for detecting the attempt itself and the delivery mechanism. The PowerShell script block logging captures the complete attack methodology and parameters, while the COM error provides a clear failure indicator.

The dataset effectively demonstrates how environmental factors (missing Office installation or COM registration issues) can prevent technique execution while still generating detectable preparatory activities. For detection engineering focused on the full attack chain rather than just successful task creation, this data shows the reconnaissance and setup phases that precede the actual persistence mechanism.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Script Downloads**: Monitor EID 4104 for scripts downloading known red team tools from GitHub, specifically patterns like `iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"`.

2. **Invoke-MalDoc Function Definition**: Alert on PowerShell script blocks containing the Invoke-MalDoc function signature or calls to `New-Object -ComObject "Word.Application"` or `"Excel.Application"`.

3. **VBA Registry Manipulation Attempts**: Watch for PowerShell commands attempting to set `HKCU:\Software\Microsoft\Office\*\*\Security\AccessVBOM` to enable VBA object model access.

4. **COM Object Instantiation Failures**: Monitor PowerShell EID 4100 error events for REGDB_E_CLASSNOTREG errors when attempting to create Office COM objects, indicating potential malicious document execution attempts.

5. **Atomic Red Team Artifact References**: Detect file path references to `\AtomicRedTeam\atomics\T1053.005\` or similar atomic test directories in command lines or script blocks.

6. **Process Chain Analysis**: Correlate powershell.exe processes that spawn child processes with command lines containing macro-related parameters (`-macroFile`, `-officeProduct`, `-sub`).

7. **Network Indicators**: Monitor DNS queries to raw.githubusercontent.com combined with subsequent PowerShell execution, indicating potential remote script download and execution.

8. **Failed Office Automation**: Track patterns where PowerShell attempts Office COM object creation followed by immediate process termination, suggesting blocked or failed macro execution attempts.
