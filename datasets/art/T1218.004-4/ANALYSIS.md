# T1218.004-4: InstallUtil — InstallUtil Install method call

## Technique Context

T1218.004 (InstallUtil) is a defense evasion technique where attackers abuse Microsoft's legitimate InstallUtil.exe utility to execute arbitrary code. InstallUtil is designed to install and uninstall .NET applications by calling their installer classes, but adversaries can craft malicious .NET assemblies with installer classes containing payloads that execute during the installation process. This technique is particularly valuable because InstallUtil.exe is a signed Microsoft binary that's unlikely to be blocked by application whitelisting solutions, and it can execute code from assemblies without explicitly launching them as executables.

The detection community focuses on monitoring InstallUtil process creation with unusual command-line arguments, .NET compilation activity that precedes InstallUtil execution, and the creation of suspicious installer assemblies. Key indicators include InstallUtil being launched from non-standard directories, processing assemblies with unusual extensions or in temporary locations, and unusual parent-child process relationships.

## What This Dataset Contains

This dataset captures a comprehensive InstallUtil execution where PowerShell dynamically compiles a malicious installer assembly and executes it via InstallUtil.exe. The primary evidence includes:

**InstallUtil Process Creation**: Security event 4688 shows `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false /installtype=notransaction /action=install C:\Windows\TEMP\T1218.004.dll` launched by powershell.exe. Sysmon event 1 captures the same execution with detailed hashes and integrity level information.

**Dynamic Assembly Compilation**: The test framework compiles the malicious installer assembly on-demand. Security events 4688 show two instances of csc.exe (C# compiler) with command lines like `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\e3hjswun\e3hjswun.cmdline"`. The first compilation creates T1218.004.dll in C:\Windows\Temp\.

**Assembly File Operations**: Sysmon event 11 captures the creation of T1218.004.dll and associated files like T1218.004.InstallState, showing the complete installer assembly lifecycle.

**PowerShell Test Test framework**: The PowerShell channel contains the complete test framework code in event 4104, including the Invoke-BuildAndInvokeInstallUtilAssembly function that builds the installer assembly with constructor and Install method implementations that write to temporary files for validation.

**Process Access Events**: Multiple Sysmon event 10 entries show PowerShell accessing the spawned processes (whoami.exe, csc.exe, InstallUtil.exe) with PROCESS_ALL_ACCESS (0x1FFFFF), indicating process monitoring behavior typical of the test framework.

## What This Dataset Does Not Contain

The dataset lacks several elements that would strengthen InstallUtil detection:

**Sysmon ProcessCreate Filtering**: The sysmon-modular configuration's include-mode filtering means we're missing ProcessCreate events for standard processes. While we see InstallUtil.exe creation, we might be missing other relevant process spawns.

**Assembly Content Analysis**: While we see the test framework PowerShell code, we don't have visibility into the actual C# source code of the compiled installer assembly or its specific malicious behaviors beyond file writes.

**Network Activity**: There are no DNS queries or network connections showing potential command-and-control communication that might occur in real InstallUtil abuse scenarios.

**Persistence Mechanisms**: This test focuses on execution but doesn't demonstrate how InstallUtil might be used to establish persistence through scheduled tasks or registry modifications.

## Assessment

This dataset provides excellent telemetry for InstallUtil detection engineering. The combination of Security event 4688 process creation logs and Sysmon events creates comprehensive coverage of the technique execution. The PowerShell script block logging captures the complete attack methodology, while the file creation events document the assembly compilation and deployment process. The process access events add valuable context about the relationships between components.

The data quality is high with detailed command lines, file hashes, and parent-child process relationships clearly documented. The test framework approach means the execution is successful and generates the expected InstallUtil behaviors that defenders need to detect.

## Detection Opportunities Present in This Data

1. **InstallUtil Process Creation**: Monitor Security 4688 and Sysmon 1 for InstallUtil.exe spawned by unusual parents (PowerShell, cmd.exe) or processing assemblies in temporary directories like `C:\Windows\TEMP\`.

2. **Dynamic Assembly Compilation**: Alert on csc.exe (C# compiler) execution followed by InstallUtil.exe within a short time window, especially when both share the same parent process.

3. **Suspicious Assembly Locations**: Flag InstallUtil processing .dll files in user-writable locations like %TEMP%, %APPDATA%, or system temporary directories rather than standard installation paths.

4. **PowerShell and .NET Compiler Correlation**: Detect PowerShell processes spawning both csc.exe and InstallUtil.exe in sequence, indicating dynamic malware compilation and execution.

5. **InstallUtil Command-Line Arguments**: Monitor for InstallUtil with arguments like `/logfile=` (empty log file), `/logtoconsole=false`, or `/installtype=notransaction` that may indicate evasive usage.

6. **File Creation Patterns**: Alert on rapid creation of .dll files followed by .InstallState files in temporary directories, indicating installer assembly deployment and execution.

7. **Process Access Monitoring**: Use Sysmon 10 events to detect when PowerShell or other scripting engines obtain excessive access rights to InstallUtil.exe processes.

8. **Assembly File Extensions**: Monitor InstallUtil processing files with non-standard extensions, as attackers often use .txt, .log, or other extensions to evade detection while maintaining assembly functionality.
