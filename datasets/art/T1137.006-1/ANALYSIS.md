# T1137.006-1: Add-ins — Code Executed Via Excel Add-in File (XLL)

## Technique Context

T1137.006 (Office Application Startup: Add-ins) represents a persistence technique where attackers abuse Microsoft Office add-ins to maintain access to systems. Excel add-ins, specifically XLL files, are dynamic link libraries that integrate with Excel to provide additional functionality. Attackers can create malicious XLL files that execute code when Excel loads them, either through registry entries or by placing them in Excel's startup folders.

This technique is particularly valuable to attackers because it leverages trusted Office applications, often bypasses application whitelisting, and provides a persistent foothold that survives reboots. The detection community focuses on monitoring for unusual XLL file creation, registry modifications in Office add-in locations, and unexpected Excel processes loading suspicious libraries.

## What This Dataset Contains

This dataset captures a failed Excel XLL add-in registration attempt due to the absence of Microsoft Office on the test system. The PowerShell script attempts to instantiate an Excel COM object and register either a 64-bit or 32-bit XLL file located at `C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\excelxll_x64.xll` or `excelxll_x86.xll`.

Key events include:
- **Security 4688**: PowerShell process creation with the full command line showing the Excel COM object creation attempt: `"powershell.exe" & {$excelApp = New-Object -COMObject "Excel.Application"`
- **PowerShell 4104**: Script block logging capturing the actual XLL registration code attempting to call `$excelApp.RegisterXLL()`
- **PowerShell 4100**: COM error showing the technique failed: "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered"
- **Sysmon 1**: Process creation events for the PowerShell processes spawned during execution
- **Sysmon 7**: Image loads showing .NET runtime components loading into PowerShell processes
- **Sysmon 10**: Process access events showing PowerShell accessing child processes
- **Sysmon 11**: File creation events for PowerShell startup profile data

## What This Dataset Does Not Contain

The dataset lacks the core technique execution because Microsoft Office is not installed on the test system. Missing elements include:
- Excel.exe process creation and execution
- Actual XLL file loading into Excel's process space
- Registry modifications that would occur during successful add-in registration
- Office-specific telemetry that would show add-in initialization
- File system events showing XLL files being accessed or executed
- Network connections or other post-exploitation activities that would follow successful persistence establishment

The COM error (REGDB_E_CLASSNOTREG) definitively shows the Excel application object could not be instantiated, preventing the RegisterXLL method from being called.

## Assessment

This dataset provides limited value for detecting successful T1137.006 implementations since the core technique fails at the COM instantiation stage. However, it demonstrates valuable detection opportunities for attempted Office-based attacks and provides insight into how attackers might probe for Office availability.

The PowerShell script block logging captures the exact malicious intent even when execution fails, which is valuable for threat hunting. The Security 4688 events with full command lines also provide detection opportunities for similar attack patterns.

For building detections of successful XLL add-in abuse, this dataset would need to be supplemented with execution on a system with Microsoft Office installed.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis**: Monitor PowerShell 4104 events for script blocks containing "Excel.Application", "RegisterXLL", and XLL file paths
2. **Command Line Hunting**: Alert on Security 4688 events with command lines containing COM object creation patterns for Office applications combined with file extensions like ".xll"
3. **COM Instantiation Monitoring**: Track PowerShell 4100 error events indicating failed COM object creation for Office applications as potential reconnaissance
4. **Process Tree Analysis**: Detect PowerShell spawning from unexpected parents attempting to interact with Office COM objects
5. **File Path Indicators**: Monitor for references to common Atomic Red Team test paths like `C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\`
6. **PowerShell Module Loading**: Correlate Sysmon 7 events showing .NET runtime loading with PowerShell processes executing Office-related COM operations
