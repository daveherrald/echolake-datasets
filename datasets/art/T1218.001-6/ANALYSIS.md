# T1218.001-6: Compiled HTML File — Invoke CHM with Script Engine and Help Topic

## Technique Context

T1218.001 involves abusing Microsoft Compiled HTML Help (CHM) files to execute malicious code while bypassing application control mechanisms. CHM files are legitimate Windows help documentation containers that can embed HTML content, including JavaScript and VBScript. Attackers exploit this by crafting malicious CHM files containing script engines that execute upon opening. The technique leverages the Microsoft HTML Help executable (hh.exe) as a trusted signed binary to proxy execution of malicious scripts. This specific test demonstrates invoking a CHM file with embedded JScript using the Information Technology Storage (ITS) handler and HTML topic extension, simulating how attackers might deliver payloads disguised as legitimate help documentation.

## What This Dataset Contains

The dataset captures the execution chain of the Atomic Red Team test invoking a malicious CHM file. The Security event logs show the complete process creation sequence with Security EID 4688 capturing the PowerShell process spawning with command line `"powershell.exe" & {Invoke-ATHCompiledHelp -ScriptEngine JScript -InfoTechStorageHandler its -TopicExtension html -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}`. The PowerShell execution events in EID 4104 reveal the actual technique invocation: `& {Invoke-ATHCompiledHelp -ScriptEngine JScript -InfoTechStorageHandler its -TopicExtension html -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}`.

Sysmon captures extensive process telemetry including EID 1 events for both the initial whoami.exe execution (PID 15536) and the subsequent PowerShell process (PID 41008) that would execute the CHM invocation. Multiple EID 7 image load events show .NET framework components loading into PowerShell processes, including System.Management.Automation assemblies. Notably absent from the dataset are any process creation events for hh.exe itself, suggesting the CHM execution portion may have been blocked or failed to complete.

## What This Dataset Does Not Contain

Most critically, this dataset lacks evidence of the actual hh.exe process execution that would demonstrate the core technique behavior. There are no Sysmon EID 1 process creation events for hh.exe, no corresponding Security 4688 events for HTML Help executable launch, and no network connections or file operations that would indicate successful CHM processing. The absence of hh.exe execution suggests Windows Defender may have blocked the technique before the malicious CHM could be processed, or the test CHM file may not have been properly constructed. Additionally, there are no file creation events showing the Test.chm file being written to disk, and no DNS queries or network connections that might result from successful script execution within the CHM context.

## Assessment

The dataset provides limited value for understanding the complete T1218.001 technique execution due to the apparent failure or blocking of the core hh.exe invocation. While the PowerShell command lines clearly show the intended technique parameters (JScript engine, ITS handler, HTML topic extension), the absence of the actual CHM processing significantly reduces detection utility. The Security and PowerShell logs effectively capture the initial preparation and invocation attempt, which could be valuable for detecting the setup phase of CHM-based attacks. However, without the hh.exe execution and subsequent script processing, defenders cannot observe the full attack chain or develop comprehensive detections for the technique's completion.

## Detection Opportunities Present in This Data

1. **PowerShell CHM Invocation Detection**: Monitor PowerShell script block logging (EID 4104) for functions like "Invoke-ATHCompiledHelp" or command patterns containing "ScriptEngine", "InfoTechStorageHandler", and ".chm" parameters that indicate CHM-based execution attempts.

2. **Suspicious PowerShell Command Line Analysis**: Detect Security EID 4688 process creation events where powershell.exe command lines contain references to hh.exe, CHM files, and script engine parameters, particularly when combined with environment variable expansion like "$env:windir\hh.exe".

3. **PowerShell Process Chain Monitoring**: Track PowerShell processes (via Sysmon EID 1) that spawn additional PowerShell instances with command lines referencing compiled help files or HTML help executables, indicating potential defense evasion attempts.

4. **Execution Policy Bypass Detection**: Monitor PowerShell EID 4103 command invocation events for "Set-ExecutionPolicy" with "Bypass" scope, often used in conjunction with malicious script execution techniques.

5. **Process Access Pattern Analysis**: Correlate Sysmon EID 10 process access events showing PowerShell processes accessing spawned child processes with full access rights (0x1FFFFF), which may indicate injection or manipulation attempts related to the CHM execution chain.
