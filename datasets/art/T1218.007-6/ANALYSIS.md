# T1218.007-6: Msiexec — WMI Win32_Product Class - Execute Local MSI file with embedded VBScript

## Technique Context

T1218.007 (Msiexec) is a defense evasion technique where attackers abuse the legitimate Windows Installer service (msiexec.exe) to proxy execution of malicious code. Attackers leverage msiexec because it's a signed Microsoft binary that can execute arbitrary code during MSI installation processes, making it an effective "living off the land" technique. This specific test demonstrates using WMI's Win32_Product class to invoke msiexec programmatically, which adds an additional layer of indirection through PowerShell and WMI. The embedded VBScript in the MSI package executes during installation, showcasing how attackers can package malicious scripts within seemingly legitimate installer files. Detection engineers focus on unusual msiexec command lines, WMI calls to Win32_Product, and the loading of script execution libraries (vbscript.dll, amsi.dll) within msiexec processes.

## What This Dataset Contains

This dataset captures a complete execution chain starting with PowerShell invoking `Invoke-CimMethod -ClassName Win32_Product -MethodName Install` to install an MSI file containing embedded VBScript. The Security channel shows the full process tree: an initial PowerShell process (PID 32656) spawning a child PowerShell process (PID 14072) with the command line `"powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_VBScript.msi' }}`. This triggers msiexec.exe (PID 24948) which then spawns a second msiexec process (PID 32008) with the command line `C:\Windows\System32\MsiExec.exe -Embedding 9D84316442BD365C3F1C654CFA49FEFD E Global\MSI0000`. 

The Sysmon data reveals critical execution artifacts: the second msiexec process loads vbscript.dll, wshom.ocx (Windows Script Host Runtime Library), scrrun.dll (Script Runtime), and amsi.dll, indicating script execution capabilities. Most importantly, this msiexec process spawns PowerShell (PID 19896) with the command line `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -Command Write-Host VBScript executed me!; exit`, which is the payload from the embedded VBScript. The PowerShell logs capture the actual script execution with EID 4104 showing the script block `Write-Host VBScript executed me!; exit` and EID 4103 showing the Write-Host command invocation.

Application logs document the MSI installation lifecycle with events showing the installer transaction beginning (EID 1040), successful installation completion (EID 11707, 1033), and transaction ending (EID 1042) for "Atomic Red Team Test Installer" version 1.0.0.

## What This Dataset Does Not Contain

The dataset lacks file system monitoring beyond basic file creation events, missing detailed file operations during the MSI extraction and installation process. Network monitoring is absent, so any potential network communications during installation aren't captured. Registry modification events aren't present, though MSI installations typically create registry entries. The dataset doesn't show the MSI file's internal structure or how the VBScript was embedded within it. Additionally, there's no evidence of Windows Defender actively blocking or alerting on this technique, suggesting the test MSI wasn't flagged as malicious by the endpoint protection.

## Assessment

This dataset provides excellent coverage for detecting T1218.007 via WMI Win32_Product abuse. The combination of Security event 4688 process creation logs with full command lines and Sysmon process creation events (EID 1) with detailed parent-child relationships creates a clear detection foundation. The presence of Security 4703 privilege escalation events for msiexec processes adds context about elevated execution. Sysmon image load events (EID 7) are particularly valuable, showing the loading of script execution libraries within msiexec. The PowerShell script block logging provides definitive evidence of the payload execution. Application events offer supplementary context about the installation process. The main limitation is the lack of Sysmon ProcessCreate events for the initial PowerShell processes due to include-mode filtering, but Security 4688 events compensate for this gap.

## Detection Opportunities Present in This Data

1. **WMI Win32_Product Installation via PowerShell** - PowerShell script blocks containing `Invoke-CimMethod -ClassName Win32_Product -MethodName Install` indicate programmatic MSI installation abuse

2. **Msiexec Spawning PowerShell** - Process creation events showing msiexec.exe as parent process launching powershell.exe, indicating embedded script execution within MSI packages

3. **Script Execution Libraries in Msiexec** - Sysmon EID 7 showing msiexec loading vbscript.dll, wshom.ocx, scrrun.dll, or jscript.dll indicates embedded script execution capabilities

4. **Msiexec Embedding Parameter** - Command lines containing `msiexec.exe -Embedding` with GUIDs suggest COM activation for MSI installation, often seen in programmatic installations

5. **Privilege Escalation During MSI Installation** - Security EID 4703 showing SeRestorePrivilege and SeTakeOwnershipPrivilege being enabled for msiexec processes indicates elevated installation activities

6. **PowerShell NoProfile Execution from Msiexec** - PowerShell command lines with `-nop` parameter spawned by msiexec processes suggest embedded script payload execution

7. **MSI File Staging to Windows Installer Directory** - File creation events showing .msi files being copied to C:\Windows\Installer\ directory with random filenames indicate MSI staging for installation

8. **AMSI Loading in Msiexec Context** - Sysmon EID 7 showing amsi.dll loading within msiexec processes indicates script content being scanned, suggesting embedded script execution
