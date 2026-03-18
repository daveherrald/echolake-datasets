# T1218.007-7: Msiexec — WMI Win32_Product Class - Execute Local MSI file with an embedded DLL

## Technique Context

T1218.007 (Msiexec) represents the abuse of Microsoft's Windows Installer (msiexec.exe) to execute malicious code while appearing legitimate. Attackers leverage msiexec because it's a trusted system binary that can install packages, execute custom actions, and run with elevated privileges. The detection community focuses on unusual msiexec command lines, network connections to suspicious sources, and the execution of embedded code within MSI packages. This specific test variant uses WMI's Win32_Product class to trigger MSI installation, demonstrating how attackers can programmatically deploy malicious MSI packages through PowerShell and WMI interfaces.

## What This Dataset Contains

The dataset captures a complete execution chain showing PowerShell-initiated MSI installation via WMI. Security event 4688 shows the initial PowerShell command: `"powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_DLL.msi' }}`. The process chain continues through msiexec spawning with command line `C:\Windows\System32\MsiExec.exe -Embedding BEA870C538981580C7883B82B7EE186C E Global\MSI0000`, indicating COM-based MSI execution.

The dataset shows successful MSI installation through Application events: EID 1040 "Beginning a Windows Installer transaction", EID 11707 "Installation completed successfully", and EID 1033 showing the installed product "Atomic Red Team Test Installer". The embedded DLL execution is evidenced by msiexec spawning PowerShell with command `powershell.exe -nop -Command Write-Host CustomAction export executed me; exit`, demonstrating custom action execution within the MSI package.

Sysmon captures extensive process creation (EID 1) and image loading (EID 7) events throughout the execution chain, including multiple PowerShell instances and the specific msiexec processes. File creation events (EID 11) show MSI staging in `C:\Windows\Installer\327edf8.msi` and temporary file creation. PowerShell script block logging (EID 4104) captures the WMI method invocation and the executed custom action command.

## What This Dataset Does Not Contain

The dataset lacks network-based MSI installation scenarios since this test uses a local MSI file. Registry modifications that typically accompany MSI installations are not captured due to the audit policy configuration focusing on process and command-line logging rather than object access. The actual DLL payload behavior beyond the simple PowerShell command execution is not present, as this is a proof-of-concept rather than a malicious payload deployment.

Sysmon ProcessCreate events are limited due to the include-mode filtering, potentially missing some child processes that don't match suspicious patterns. The PowerShell channel contains primarily test framework boilerplate rather than the actual malicious PowerShell execution, which appears mainly in Security event command lines and limited script block logging.

## Assessment

This dataset provides excellent coverage for detecting T1218.007 abuse via WMI interfaces. The combination of Security 4688 command-line logging, Application events showing successful MSI operations, and Sysmon process creation events offers multiple detection vectors. The clear process ancestry from PowerShell through msiexec to custom action execution provides strong behavioral indicators.

The data quality is high for building detections around WMI-based MSI deployment, unusual msiexec command patterns, and embedded code execution within MSI packages. The presence of both the trigger mechanism (Invoke-CimMethod) and the execution evidence (msiexec spawning PowerShell) makes this dataset particularly valuable for comprehensive detection rule development.

## Detection Opportunities Present in This Data

1. PowerShell execution of `Invoke-CimMethod` with `Win32_Product` class and `Install` method targeting MSI files in Security 4688 events

2. Msiexec.exe spawning with `-Embedding` parameter and COM interface identifiers in command lines

3. Process ancestry chains showing PowerShell → msiexec.exe → PowerShell indicating custom action execution

4. Application events showing rapid MSI installation transactions (EID 1040/1042) combined with successful installation messages

5. File creation events in `C:\Windows\Installer\` directory with MSI and temporary file staging

6. PowerShell script block logging containing `Invoke-CimMethod` with MSI package location arguments

7. Msiexec.exe spawning PowerShell with `-nop -Command` parameters indicating custom action script execution

8. Privilege escalation indicators through Security 4703 events showing SeRestorePrivilege and SeTakeOwnershipPrivilege activation by msiexec

9. Multiple PowerShell process creations within short time windows associated with MSI installation workflows

10. Sysmon process creation events with msiexec parent processes spawning unexpected child processes like PowerShell
