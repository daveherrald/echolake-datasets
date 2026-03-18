# T1137.006-5: Add-ins — Persistent Code Execution Via PowerPoint VBA Add-in File (PPAM)

## Technique Context

T1137.006 focuses on Office application add-ins as a persistence mechanism. Adversaries leverage legitimate Office extensibility features to maintain persistence by deploying malicious add-ins that execute automatically when the host application starts. PowerPoint Add-in Manager (PPAM) files are VBA-enabled add-ins that can contain arbitrary code and are automatically loaded by PowerPoint when properly registered. This technique is particularly valuable to attackers because it provides legitimate-looking persistence within a commonly-used application, often bypassing security controls that focus on traditional persistence mechanisms. The detection community typically monitors for unexpected add-in registrations, file operations in Office add-in directories, and registry modifications to Office add-in paths.

## What This Dataset Contains

This dataset captures a failed attempt to establish PowerPoint VBA add-in persistence. The technique execution is visible in Security event 4688 showing PowerShell spawning with the full attack command line: `"powershell.exe" & {Copy \"C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\PptVBAaddin.ppam\" \"$env:APPDATA\Microsoft\Addins\notepad.ppam\"`. The PowerShell script block logging in event 4104 reveals the complete attack payload, including file copy operations, COM object creation attempts, and registry manipulation.

Despite the file copy failure (PowerShell error 4102: "Could not find a part of the path"), the technique proceeds to set registry keys. Sysmon event 13 captures two registry value modifications: `HKU\.DEFAULT\Software\Microsoft\Office\PowerPoint\AddIns\notepad\Autoload` set to DWORD 1 and `HKU\.DEFAULT\Software\Microsoft\Office\PowerPoint\AddIns\notepad\Path` set to "notepad.ppam". The script also attempts PowerPoint COM automation with `New-Object -COMObject "PowerPoint.Application"` but fails with error 0x80040154 (Class not registered), and tries launching PowerPoint with `Start-Process "PowerPnt"` which fails because the executable doesn't exist.

Process creation telemetry shows the full process chain: initial PowerShell (PID 23580) → whoami.exe (PID 23308) → child PowerShell (PID 38016) executing the attack script. Sysmon process access events (EID 10) capture inter-process communication during the execution.

## What This Dataset Does Not Contain

The dataset lacks several critical components due to the test environment limitations. Most notably, PowerPoint is not installed on this system, causing the COM object instantiation and process launch attempts to fail. This means we don't see the actual PPAM file placement in the target directory (`$env:APPDATA\Microsoft\Addins\notepad.ppam`) or subsequent PowerPoint loading behavior. 

The source PPAM file (`C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\PptVBAaddin.ppam`) is also missing from the system, preventing the file copy operation from succeeding. Network-based telemetry is absent as this technique operates entirely through local file and registry operations. The registry modifications target the .DEFAULT user hive rather than the current user's hive, which may not reflect realistic attack scenarios where user-specific persistence is the goal.

## Assessment

This dataset provides excellent visibility into the PowerShell-based attack vector for Office add-in persistence, with comprehensive command-line logging and registry modification telemetry. The Security 4688 events with full command-line logging and PowerShell script block logging (4104) offer complete attack reconstruction capabilities. The Sysmon registry monitoring (EID 13) captures the persistence mechanism establishment perfectly.

However, the failed execution significantly limits the dataset's utility for understanding successful attack completion and post-exploitation behavior. The absence of PowerPoint prevents observation of the add-in loading process, which is crucial for understanding the full attack lifecycle. For detection engineering focused on early-stage indicators (PowerShell execution patterns, registry modifications), this data is valuable. For understanding complete attack chains or building detections around successful add-in execution, additional datasets with proper Office installations would be needed.

## Detection Opportunities Present in This Data

1. PowerShell command-line detection for Office add-in manipulation patterns, specifically looking for `$env:APPDATA\Microsoft\Addins` path references in process command lines

2. Registry monitoring for Office add-in registration, particularly `HKEY_USERS\*\Software\Microsoft\Office\*\*\AddIns\*` keys with `Autoload` and `Path` value creation

3. File operation monitoring for PPAM file placement in user add-in directories (`%APPDATA%\Microsoft\Addins\*.ppam`)

4. PowerShell script block analysis for COM object creation attempts targeting "PowerPoint.Application" combined with add-in registration activities

5. Process creation chains involving PowerShell spawning with Office application parameters or add-in related file operations

6. Behavioral detection combining PowerShell execution with Office add-in registry key creation within close temporal proximity

7. Anomaly detection for Office add-in registration attempts when the target Office application is not installed or available
