# T1047-7: Windows Management Instrumentation — Create a Process using WMI Query and an Encoded Command

## Technique Context

T1047 Windows Management Instrumentation is a critical execution technique where attackers leverage WMI's process creation capabilities to execute code on local or remote systems. This specific test demonstrates WMI process creation combined with PowerShell command encoding—a common evasion pattern where attackers use base64-encoded PowerShell commands to obfuscate their intent. The detection community focuses on WMI process creation events, particularly when they spawn unusual processes or use encoded commands, as these patterns frequently indicate malicious activity. WMI execution is particularly concerning because it can appear legitimate (system processes creating other system processes) while providing powerful execution capabilities that bypass many application control mechanisms.

## What This Dataset Contains

This dataset captures a successful WMI-based process creation with command encoding. The attack chain begins with PowerShell executing an encoded command: `powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA` which decodes to `Invoke-WmiMethod -Path win32_process -Name create -ArgumentList notepad.exe`.

The telemetry shows the complete process chain: initial PowerShell → cmd.exe → second PowerShell (with encoded command) → WmiPrvSE.exe → notepad.exe. Security event 4688 captures the cmd.exe creation with the full encoded command line, while Sysmon event 1 captures the final PowerShell execution with the same encoded payload. The critical WMI evidence appears in Sysmon event 1 showing notepad.exe created by WmiPrvSE.exe (PID 4844) rather than directly by PowerShell, and PowerShell event 4103 capturing the `Invoke-WmiMethod` command invocation with parameters `Path="win32_process"`, `Name="create"`, and `ArgumentList="notepad.exe"`.

Sysmon event 7 captures the loading of `wmiutils.dll` by PowerShell, providing additional evidence of WMI activity. Process access events (Sysmon 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating the parent-child relationship establishment.

## What This Dataset Does Not Contain

The dataset lacks network telemetry that would show remote WMI connections, as this test executes locally. While the technique successfully creates the target process (notepad.exe), the notepad process exits quickly with status 0xC0150002 (side-by-side configuration error), likely due to the GUI application running in a headless environment. The dataset doesn't capture WMI repository access or CIM operations that might provide additional detection opportunities. ETW events from the Microsoft-Windows-WMI-Activity provider are not included, which would show detailed WMI method invocations and WQL queries.

## Assessment

This dataset provides excellent coverage for detecting WMI-based process creation combined with PowerShell command encoding. The combination of Security 4688 events with full command-line logging and Sysmon's process creation, DLL loading, and process access events creates multiple detection opportunities. The encoded command pattern is clearly visible across multiple telemetry sources, and the WmiPrvSE.exe parent process relationship provides a strong WMI execution indicator. The PowerShell operational logs capture both the encoded execution and the decoded WMI method invocation, giving defenders visibility into both the obfuscation technique and the underlying attack method.

## Detection Opportunities Present in This Data

1. **Encoded PowerShell Command Detection** - Security 4688 and Sysmon 1 events showing PowerShell with `-e` or `-EncodedCommand` parameters containing base64 strings

2. **WMI Process Creation Parent-Child Anomaly** - Sysmon 1 events where legitimate processes (notepad.exe) are created by WmiPrvSE.exe instead of expected parent processes

3. **PowerShell WMI Method Invocation** - PowerShell 4103 events showing `Invoke-WmiMethod` commands targeting `win32_process` with `create` method

4. **WMI DLL Loading Pattern** - Sysmon 7 events showing PowerShell loading `wmiutils.dll` followed by process creation

5. **Process Chain Analysis** - Security 4688 sequence showing PowerShell → cmd.exe → PowerShell with encoded commands indicating process injection or lateral execution

6. **Base64 Command Decoding** - Static analysis of the base64 string `SQBuAHYAbwBrAGUALQBX...` revealing `Invoke-WmiMethod` commands

7. **PowerShell Execution Policy Bypass** - PowerShell 4103 events showing `Set-ExecutionPolicy` with `Bypass` parameter combined with encoded execution

8. **High-Privilege Process Access** - Sysmon 10 events showing PowerShell accessing multiple processes with full access rights (0x1FFFFF) during WMI operations
