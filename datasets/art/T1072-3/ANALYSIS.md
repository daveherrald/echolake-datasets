# T1072-3: Software Deployment Tools — Deploy 7-Zip Using Chocolatey

## Technique Context

T1072 (Software Deployment Tools) covers adversaries leveraging legitimate software deployment and administration tools to move laterally through environments and execute code on remote systems. These tools, including package managers like Chocolatey, configuration management systems, and remote administration utilities, provide built-in capabilities for software installation, system configuration, and remote execution that adversaries can abuse. The detection community focuses on identifying unusual deployment tool usage patterns, monitoring for suspicious package installations, tracking command-line arguments that indicate malicious intent, and correlating deployment activities with other attack indicators.

## What This Dataset Contains

This dataset captures a Chocolatey package installation attempt that appears to have failed. The Security channel shows two PowerShell processes - the parent PowerShell process (PID 26572) executing `"powershell.exe"` and spawning a child PowerShell process (PID 19100) with the command line `"powershell.exe" & {# Deploy 7-Zip using Chocolatey\nchoco install -y 7zip}`. The PowerShell script block logging in EID 4104 events shows the actual technique payload: `choco install -y 7zip`.

Sysmon captures the process creation chain with EID 1 events showing the spawning of both processes. The parent PowerShell process also executes `whoami.exe` (captured in both Sysmon EID 1 and Security EID 4688), indicating some system reconnaissance. The dataset includes extensive image loading events (EID 7) showing .NET Framework components, PowerShell automation assemblies, and Windows Defender integration DLLs being loaded into both PowerShell processes.

Notably absent from the telemetry is any evidence of the actual `choco.exe` process execution, suggesting the Chocolatey installation command failed or was blocked before execution. The PowerShell processes exit cleanly (exit status 0x0 in Security EID 4689 events), indicating controlled termination rather than forced termination by security controls.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence of successful T1072 execution - there are no process creation events for `choco.exe` itself, nor any child processes that would indicate package downloading, installation, or the deployment of the 7-Zip software. This suggests either Chocolatey is not installed on the system, the command failed due to network restrictions, or Windows Defender blocked the execution before it could proceed.

The telemetry also doesn't show network connections that would be expected during package downloads, file system modifications in typical Chocolatey installation directories (like `C:\ProgramData\chocolatey\`), or registry changes associated with software installation. There are no Windows Application events that might indicate package manager activity or installation attempts.

## Assessment

This dataset provides limited value for detection engineering focused on successful T1072 execution, as it primarily captures the attempt rather than the actual software deployment tool abuse. However, it does offer good visibility into the preparatory phases of the technique - the PowerShell script execution, command-line arguments, and process spawning patterns that would be common precursors to successful deployment tool abuse.

The Security channel with command-line logging provides excellent coverage of the attack initiation, while Sysmon adds valuable process ancestry and image loading context. The PowerShell logging successfully captures the script blocks, though the attempt appears to fail at the actual tool execution phase.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection** - Security EID 4688 events contain the explicit command `"powershell.exe" & {# Deploy 7-Zip using Chocolatey\nchoco install -y 7zip}` which can detect Chocolatey usage patterns

2. **Script Block Analysis** - PowerShell EID 4104 events capture the script block content `choco install -y 7zip`, enabling detection of package manager commands in PowerShell execution

3. **Process Ancestry Monitoring** - Sysmon EID 1 events show PowerShell spawning child PowerShell processes with suspicious command lines, indicating potential lateral movement preparation

4. **System Discovery Correlation** - The execution of `whoami.exe` (Sysmon EID 1, Security EID 4688) in conjunction with deployment tool commands suggests reconnaissance activities

5. **PowerShell Nested Execution** - The parent-child PowerShell relationship with different command lines indicates potential script-based deployment attempts

6. **Package Manager Command Detection** - String matching on "choco install" patterns in command lines and script blocks can identify Chocolatey abuse attempts

7. **Administrative Tool Usage Patterns** - Detection of software deployment commands executed from non-standard execution contexts or by unexpected user accounts
