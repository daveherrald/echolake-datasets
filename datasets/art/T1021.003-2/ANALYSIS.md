# T1021.003-2: Distributed Component Object Model — PowerShell Lateral Movement Using Excel Application Object

## Technique Context

T1021.003 Distributed Component Object Model (DCOM) is a lateral movement technique where attackers abuse Microsoft's DCOM infrastructure to execute code on remote systems. DCOM allows objects to communicate across network boundaries, and Windows exposes numerous applications through DCOM that can be leveraged for remote execution. The detection community focuses on unusual DCOM object instantiation, particularly COM objects like Excel.Application, MMC20.Application, and ShellBrowserWindow that provide code execution capabilities. This specific test attempts to use Excel.Application's ActivateMicrosoftApp method to execute a renamed calculator binary, simulating how attackers might abuse Office applications for lateral movement.

## What This Dataset Contains

The telemetry captures a failed lateral movement attempt using DCOM and Excel.Application. Security event 4688 shows the main PowerShell execution with command line `"powershell.exe" & {copy c:\windows\system32\calc.exe 'C:\users\admin\AppData\local\Microsoft\WindowsApps\foxprow.exe'; $com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"Excel.Application\",\"localhost\")); $com.ActivateMicrosoftApp(\"5\")}`. The PowerShell channel captures the actual script blocks showing COM object instantiation via `[System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","localhost"))` and the subsequent call to `$com.ActivateMicrosoftApp("5")`. However, PowerShell events 4102/4100 reveal the technique failed due to a filesystem error: "Could not find a part of the path 'C:\users\admin\AppData\local\Microsoft\WindowsApps\foxprow.exe'". Sysmon captures extensive .NET runtime loading events (EID 7) as PowerShell initializes the COM subsystem, process access events (EID 10) showing PowerShell accessing spawned processes, and named pipe creation (EID 17) for PowerShell's internal communication.

## What This Dataset Does Not Contain

The dataset lacks the core evidence of successful DCOM lateral movement because the technique failed at the file copy stage. There are no Excel.exe process creations, no DCOM-related network connections, no successful remote process execution, and critically no events showing Excel.Application actually being instantiated and used for execution. The technique never progresses beyond the failed file copy operation, so we miss the telemetry that would show actual DCOM object marshalling, Excel process spawning with suspicious command lines, or the execution of the renamed calc.exe binary. Additionally, there are no registry modifications, file access patterns, or network authentication events that would typically accompany successful DCOM lateral movement.

## Assessment

This dataset provides limited value for detecting successful T1021.003 DCOM attacks since the technique fails before the critical COM interactions occur. While it captures the PowerShell script blocks containing DCOM instantiation code and shows .NET/COM subsystem initialization, it doesn't demonstrate the behavioral patterns analysts need to detect active DCOM abuse. The most valuable aspect is the PowerShell script block logging showing the exact COM object instantiation pattern (`GetTypeFromProgID("Excel.Application","localhost")`), but this represents attempt rather than success telemetry. For building robust DCOM detections, datasets showing successful Excel process spawning, DCOM network traffic, and remote execution would be far more useful.

## Detection Opportunities Present in This Data

1. **PowerShell DCOM Object Instantiation** - PowerShell event 4104 script blocks containing `System.Activator::CreateInstance` with `GetTypeFromProgID` for suspicious applications like "Excel.Application" with remote hostnames

2. **Suspicious File Copy to WindowsApps Directory** - PowerShell events 4102/4100 showing failed copy operations to `C:\users\*\AppData\local\Microsoft\WindowsApps\` with non-standard executable names

3. **COM Subsystem Initialization Patterns** - Sysmon EID 7 showing rapid loading of .NET runtime DLLs (mscoree.dll, mscoreei.dll, clr.dll) in PowerShell processes executing suspicious commands

4. **PowerShell Process Spawning with DCOM Keywords** - Security EID 4688 capturing PowerShell command lines containing DCOM-related PowerShell methods like "GetTypeFromProgID" and application names

5. **Anomalous ActivateMicrosoftApp Usage** - PowerShell script blocks calling `ActivateMicrosoftApp` method on COM objects, particularly with numeric parameters that don't correspond to standard Office application interactions
