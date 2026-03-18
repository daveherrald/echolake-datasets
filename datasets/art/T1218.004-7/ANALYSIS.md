# T1218.004-7: InstallUtil — InstallUtil HelpText Method Call

## Technique Context

T1218.004 (InstallUtil) is a defense evasion technique where attackers abuse the legitimate Microsoft .NET Framework utility InstallUtil.exe to execute malicious code. InstallUtil is designed to install and uninstall server resources by executing the installer components in specified assemblies. However, it can be weaponized to execute arbitrary .NET assemblies containing malicious code disguised as legitimate installer classes.

This specific test (T1218.004-7) focuses on the HelpText property abuse vector, where InstallUtil's help functionality (`/?` switch) triggers the execution of custom code within an installer assembly's HelpText property getter. This is a more subtle variant than traditional Install/Uninstall method abuse, as it executes code during help text display rather than during apparent installation operations.

The detection community typically focuses on monitoring InstallUtil.exe process creation with suspicious command-line arguments, especially non-standard file extensions or unusual file paths, assembly loading events, and the execution of code within installer constructors or methods.

## What This Dataset Contains

This dataset captures a successful InstallUtil HelpText property execution through PowerShell automation. The key evidence includes:

**Process Creation Chain:**
- PowerShell test framework execution in Security 4688: `"powershell.exe" & {# Import the required test framework function, Invoke-BuildAndInvokeInstallUtilAssembly`
- C# compiler invocation: `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\nsmyk035\nsmyk035.cmdline"`
- The critical InstallUtil execution: `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /? C:\Windows\TEMP\T1218.004.dll`

**Assembly Compilation Evidence:**
- Multiple Sysmon 11 events showing temporary file creation for compilation artifacts
- File creation of `C:\Windows\Temp\T1218.004.dll` - the malicious installer assembly
- PowerShell script blocks in events showing the complete test framework code that dynamically compiles an installer assembly with HelpText property abuse

**InstallUtil Execution:**
- Sysmon 1 event showing InstallUtil.exe process creation with RuleName matching T1218.004
- Security 4688 confirming the same execution
- InstallUtil exit code 0xFFFFFFFF indicating successful code execution within the HelpText property

The PowerShell script blocks reveal the complete attack methodology, including the C# source code for an installer class with a malicious HelpText property that writes to a temporary file when accessed.

## What This Dataset Does Not Contain

Several important elements are missing or limited:

**Limited Sysmon Process Coverage:** Due to the sysmon-modular include-mode filtering, many standard processes like cmd.exe and conhost.exe appear only in Security events, not Sysmon ProcessCreate events. This reduces the granularity of process tree analysis.

**No Network Activity:** This test is entirely local and generates no network connections or DNS queries.

**No Persistence Mechanisms:** The test focuses solely on execution and doesn't establish persistence or perform additional post-exploitation activities.

**Missing Assembly Loading Details:** While we see InstallUtil.exe execution, Sysmon doesn't capture the specific .NET assembly loading events that would show the malicious DLL being loaded by InstallUtil.

**Limited File System Impact:** Beyond the compilation artifacts and the test assembly, there's minimal file system modification evidence.

## Assessment

This dataset provides excellent coverage for detecting InstallUtil HelpText property abuse. The combination of Security 4688 command-line logging and Sysmon process creation events clearly shows the attack progression from PowerShell test framework to assembly compilation to InstallUtil execution. The PowerShell script block logging is particularly valuable, capturing the complete attack methodology including the malicious C# source code.

The dataset effectively demonstrates how legitimate development tools (csc.exe) can be chained with InstallUtil to execute malicious code. The presence of both the compilation phase and the execution phase makes this dataset valuable for testing detection rules that monitor for suspicious .NET Framework tool usage patterns.

The exit code evidence (0xFFFFFFFF) provides confirmation that the malicious code executed successfully, which is crucial for validating that this represents a successful attack rather than just an attempt.

## Detection Opportunities Present in This Data

1. **InstallUtil Process Creation with Help Switch**: Monitor Sysmon EID 1 or Security EID 4688 for InstallUtil.exe execution with `/?` parameter followed by suspicious DLL paths, especially in temporary directories.

2. **Suspicious Assembly Compilation Patterns**: Detect csc.exe compilation of assemblies with installer-related imports (System.Configuration.Install) in temporary directories, particularly when followed by InstallUtil execution.

3. **PowerShell Assembly Compilation and Execution Chain**: Monitor PowerShell script blocks containing Add-Type operations with installer-related code followed by InstallUtil process creation.

4. **Temporary File Creation Patterns**: Alert on creation of .dll files in %TEMP% or Windows\Temp directories followed by InstallUtil execution against those files.

5. **Process Tree Analysis**: Detect PowerShell → csc.exe → InstallUtil.exe process chains, especially when InstallUtil targets recently compiled assemblies.

6. **InstallUtil Exit Code Anomalies**: Monitor for InstallUtil processes terminating with error codes (like 0xFFFFFFFF) which may indicate successful malicious code execution rather than legitimate installation failures.

7. **Cross-Process Access Patterns**: Leverage Sysmon EID 10 events showing PowerShell accessing InstallUtil processes with high privileges (0x1FFFFF), indicating potential process manipulation or monitoring.

8. **File Extension Mismatches**: InstallUtil executing against files with .dll extension in non-standard locations (not Program Files, GAC, etc.) should trigger investigation.
