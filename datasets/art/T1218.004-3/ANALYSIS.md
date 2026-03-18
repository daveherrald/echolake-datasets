# T1218.004-3: InstallUtil — InstallUtil class constructor method call

## Technique Context

T1218.004 represents the use of InstallUtil.exe as a defense evasion technique, leveraging Microsoft's legitimate .NET Framework installation utility to execute arbitrary code. InstallUtil is designed to install and uninstall .NET assemblies that implement the System.Configuration.Install.Installer class, but attackers abuse this functionality to execute malicious code within the constructor of installer classes. This technique is particularly valuable because InstallUtil.exe is a signed Microsoft binary that can bypass application whitelisting controls and appears legitimate to security monitoring. The detection community focuses on monitoring InstallUtil executions with non-standard command-line arguments, unusual file paths, and the creation/execution of suspicious assemblies, especially when InstallUtil loads assemblies from temporary directories or user-writable locations.

## What This Dataset Contains

This dataset captures a complete InstallUtil abuse execution chain where PowerShell dynamically compiles and executes a malicious installer assembly. Security event 4688 shows the PowerShell execution with the full command line containing the test framework script: `"powershell.exe" & {# Import the required test framework function, Invoke-BuildAndInvokeInstallUtilAssembly`. The dataset includes the compilation process with two csc.exe executions (PIDs 32816 and 30864) creating the malicious assembly, followed by the critical InstallUtil.exe execution (PID 30988) with command line `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false C:\Windows\TEMP\T1218.004.dll`. Sysmon captures multiple file creation events (EID 11) showing the assembly compilation artifacts in SystemTemp directories and the final T1218.004.dll in C:\Windows\TEMP\. The PowerShell script block logging (EID 4104) reveals the complete test framework code including the installer class source code with constructor execution logic. Process access events (EID 10) show PowerShell monitoring the spawned InstallUtil process, and image load events (EID 7) capture the .NET runtime loading within InstallUtil.exe.

## What This Dataset Does Not Contain

The dataset lacks certain telemetry that would provide complete visibility into the technique execution. Notably absent are Sysmon ProcessCreate events (EID 1) for the initial PowerShell processes due to the include-mode filtering in sysmon-modular, though Security 4688 events provide process creation coverage. The dataset contains no evidence of the actual malicious code execution within the installer constructor, as this occurs within the .NET runtime and doesn't generate additional process creation or file system events. Network connection events are minimal, showing only Windows Defender telemetry. Registry modification events are absent, suggesting the installer assembly doesn't perform registry-based persistence or configuration changes. The dataset also lacks detailed memory access patterns or API call traces that would show the specific .NET methods being invoked during constructor execution.

## Assessment

This dataset provides excellent coverage for detecting InstallUtil abuse, particularly the compilation-to-execution attack chain. The combination of Security 4688 events with full command-line logging and Sysmon file creation events creates strong detection opportunities for this technique. The PowerShell script block logging is especially valuable, capturing the complete attack methodology including the custom installer class source code. However, the dataset would be stronger with Sysmon ProcessCreate events for all PowerShell processes and additional .NET runtime telemetry to capture the actual constructor execution. The file creation events provide good forensic evidence of the attack artifacts, and the process access events demonstrate the parent-child relationship monitoring that's characteristic of this technique.

## Detection Opportunities Present in This Data

1. InstallUtil execution with assemblies in temporary directories - Security 4688 showing InstallUtil.exe with paths containing Windows\TEMP or SystemTemp

2. Dynamic assembly compilation followed by InstallUtil execution - Sequence detection of csc.exe creating DLL files followed by InstallUtil.exe loading those same files within short time windows

3. PowerShell spawning InstallUtil processes - Process parentage analysis showing powershell.exe as parent of InstallUtil.exe

4. InstallUtil command-line patterns - Detection of /logfile= and /logtoconsole=false parameters often used to suppress legitimate installation output

5. Suspicious file creation patterns in system temp directories - Sysmon EID 11 events showing rapid creation of .cs, .dll, and compilation artifact files in SystemTemp locations

6. PowerShell script block content analysis - EID 4104 events containing installer class definitions, Add-Type operations with System.Configuration.Install references, or InstallUtil-related PowerShell functions

7. Process access patterns between PowerShell and InstallUtil - Sysmon EID 10 events showing PowerShell accessing InstallUtil processes with high-privilege access rights (0x1FFFFF, 0x1F3FFF)

8. .NET compilation artifacts in suspicious locations - File creation events for .cmdline, .tmp, and resource files in Windows\SystemTemp during active PowerShell sessions
