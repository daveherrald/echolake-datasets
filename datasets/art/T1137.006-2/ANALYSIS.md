# T1137.006-2: Add-ins — Persistent Code Execution Via Excel Add-in File (XLL)

## Technique Context

T1137.006 focuses on Office add-ins as a persistence mechanism, with Excel XLL (Excel Add-in Library) files being a particularly potent vector. XLL files are native DLLs that Excel loads to provide additional functionality, but attackers abuse this mechanism to achieve persistence and code execution. When properly configured, Excel automatically loads these add-ins at startup, making them an attractive option for maintaining access to compromised systems.

The detection community primarily focuses on monitoring for unusual XLL file placements, registry modifications that reference XLL files (particularly the Office OPEN registry keys), and suspicious process execution from Excel when loading add-ins. This technique is especially concerning because it leverages legitimate Office functionality, making detection challenging without proper monitoring of Office-specific artifacts.

## What This Dataset Contains

This dataset captures a failed attempt at implementing Excel XLL persistence. The key evidence appears in the PowerShell script block logging (EID 4104) which shows the complete attack script attempting to:

1. Create a COM object for Excel.Application: `$excelApp = New-Object -COMObject "Excel.Application"`
2. Copy an XLL file: `Copy "C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\excelxll_x64.xll" "$env:APPDATA\Microsoft\AddIns\notepad.xll"`
3. Configure registry persistence: `$ExcelRegPath="HKCU:\Software\Microsoft\Office\$Ver\Excel\Options"` and `New-ItemProperty $ExcelRegPath OPEN -value "/R notepad.xll"`
4. Launch Excel to trigger the add-in: `Start-Process "Excel"`

However, the PowerShell error events (EID 4100) reveal two critical failures:
- "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed... 80040154 Class not registered" - indicating Excel is not installed
- "This command cannot be run due to the error: The system cannot find the file specified" when attempting to start Excel

The Security event logs (EID 4688) show the PowerShell process creation with the full command line, while Sysmon captures process creation events for both whoami.exe (EID 1) and the child PowerShell process executing the XLL installation script.

## What This Dataset Does Not Contain

This dataset lacks the successful execution artifacts that would typically accompany XLL persistence:
- No registry modifications showing the OPEN key creation (due to Excel not being installed)
- No file creation events for the XLL payload being copied to the AddIns directory
- No Excel process execution or XLL loading events
- No network connections or other post-exploitation activities that would follow successful XLL execution

The absence of these artifacts is due to Microsoft Office/Excel not being installed on the test system, causing the COM object creation to fail before any persistence mechanisms could be established.

## Assessment

This dataset provides limited value for detection engineering focused on successful XLL persistence implementations. While it captures the attack attempt through PowerShell script block logging and command-line auditing, the failure to install Excel means the critical registry modifications and file operations that defenders need to detect are absent.

The dataset is most valuable for understanding the attack methodology and building detections around the preparatory phases (PowerShell script execution patterns, specific XLL-related command sequences), but lacks the successful execution telemetry needed for comprehensive detection rule development. Organizations with Office environments would benefit from datasets showing successful XLL installations and the resulting registry/file system changes.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis**: Monitor EID 4104 events containing "Excel.Application", "COMObject", and XLL file references in the same script block
2. **XLL File Operation Patterns**: Detect PowerShell commands attempting to copy files with ".xll" extensions to Microsoft AddIns directories
3. **Registry Manipulation Detection**: Alert on PowerShell scripts creating or modifying "HKCU:\Software\Microsoft\Office\*\Excel\Options" paths with OPEN properties
4. **Office COM Object Abuse**: Monitor for PowerShell creating Excel.Application COM objects, especially when combined with file operations and registry modifications
5. **Atomic Red Team Artifact Detection**: Flag PowerShell accessing "C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\" paths as potential test or attack activity
6. **Failed Office Operations**: Monitor PowerShell error events (EID 4100) with "Class not registered" messages related to Office applications as potential reconnaissance or failed attack attempts
