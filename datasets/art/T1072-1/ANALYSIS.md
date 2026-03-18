# T1072-1: Software Deployment Tools — Radmin Viewer Utility

## Technique Context

T1072 (Software Deployment Tools) focuses on adversaries abusing legitimate software deployment and management tools to execute code on remote systems. This technique spans both execution and lateral movement tactics, as attackers can use these tools to run commands locally or spread across networks. Common tools include Microsoft System Center Configuration Manager (SCCM), PsExec, remote management utilities, and third-party deployment solutions.

Radmin Viewer is a legitimate remote desktop software that allows administrators to connect to and control remote computers. While primarily used for IT support and system administration, attackers can abuse Radmin and similar remote access tools for persistence, lateral movement, and command execution. The detection community typically focuses on monitoring the execution of these tools from unexpected contexts, connections to unusual destinations, or deployment in environments where they aren't typically used.

## What This Dataset Contains

This dataset captures a straightforward attempt to execute Radmin Viewer through PowerShell command execution. The key artifacts include:

**Process Creation Chain**: Security EID 4688 shows PowerShell (PID 23920) spawning cmd.exe (PID 11444) with command line `"cmd.exe" /c "%PROGRAMFILES(x86)%/Radmin Viewer 3/Radmin.exe"`. The cmd.exe process exits with status code 0x1, indicating failure.

**Sysmon Process Creation**: EID 1 events capture the same process creations with additional context - whoami.exe execution (`"C:\Windows\system32\whoami.exe"`) and the failed Radmin launch attempt. The Sysmon events show the full command line includes double-percent environment variable expansion (`%%PROGRAMFILES(x86)%%`), which explains the execution failure.

**Process Access Monitoring**: Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating PowerShell's process management of its child processes.

**PowerShell Telemetry**: The PowerShell operational log contains only test framework boilerplate - Set-StrictMode scriptblocks and Set-ExecutionPolicy Bypass commands - with no evidence of the actual Radmin execution attempt.

**Privilege Escalation**: Security EID 4703 documents PowerShell enabling multiple high-privilege tokens including SeBackupPrivilege, SeRestorePrivilege, and SeSystemEnvironmentPrivilege.

## What This Dataset Does Not Contain

The dataset lacks several key elements due to the execution failure:

**No Radmin Process Creation**: Because the command line contains malformed environment variable syntax (`%%PROGRAMFILES(x86)%%` instead of `%PROGRAMFILES(x86)%`), the Radmin.exe process never actually starts. There are no process creation events, image loads, or network connections from Radmin itself.

**No Network Activity**: Since Radmin failed to execute, there are no Sysmon EID 3 network connection events that would typically show Radmin attempting to connect to remote systems or listening for incoming connections.

**No File System Artifacts**: The dataset contains only PowerShell profile-related file creation (EID 11) but no Radmin-specific file operations, configuration writes, or log file creation that would occur during successful execution.

**Limited PowerShell Script Content**: The PowerShell channel shows only framework boilerplate rather than the actual command execution that triggered the Radmin launch attempt.

## Assessment

This dataset provides limited value for detection engineering focused on successful T1072 abuse, as the technique execution failed due to a command-line syntax error. However, it offers valuable insight into detecting *attempted* abuse of software deployment tools, which can be equally important for security monitoring.

The Security 4688 events with command-line logging provide the strongest detection opportunity, clearly showing the attempt to execute Radmin through cmd.exe. The Sysmon EID 1 events add process lineage and hash information. The failure itself (cmd.exe exit code 0x1) could be leveraged to identify reconnaissance or testing activities where attackers haven't perfected their execution techniques.

The dataset would be significantly stronger with a successful execution showing actual Radmin process creation, potential network connections, and any configuration file modifications.

## Detection Opportunities Present in This Data

1. **Command Line Pattern Detection**: Monitor Security EID 4688 for cmd.exe executions containing "Radmin" or paths to remote management tools, particularly when spawned from scripting environments like PowerShell.

2. **Process Tree Analysis**: Detect PowerShell -> cmd.exe -> remote management tool execution chains through Sysmon EID 1 parent-child relationships and Security EID 4688 creator process tracking.

3. **Failed Execution Monitoring**: Alert on cmd.exe processes exiting with error codes (exit status 0x1) when attempting to execute remote administration tools, indicating potential reconnaissance or misconfigured attacks.

4. **Privilege Token Adjustment**: Monitor Security EID 4703 for PowerShell processes enabling high-privilege tokens like SeBackupPrivilege and SeRestorePrivilege in conjunction with remote tool execution attempts.

5. **Process Access Patterns**: Use Sysmon EID 10 to identify PowerShell processes accessing command interpreter processes with full access rights (0x1FFFFF) during suspected deployment tool abuse.

6. **Environment Variable Abuse Detection**: Look for command lines containing double-percent environment variable syntax (`%%VARIABLE%%`) which may indicate copy-paste errors from documentation or scripts during attack attempts.
