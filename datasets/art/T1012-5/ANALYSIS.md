# T1012-5: Query Registry — Check Software Inventory Logging (SIL) status via Registry

## Technique Context

T1012 (Query Registry) is a fundamental discovery technique where adversaries query the Windows Registry to gather system information, configuration details, or identify security software and defensive measures. The registry serves as a central database containing critical system and application configuration data, making it a valuable reconnaissance target.

This specific test focuses on Software Inventory Logging (SIL), a Windows feature that helps organizations track Microsoft software installed across their environment. Attackers might query SIL status to understand the monitoring capabilities of a target system or to assess whether their activities might be logged. The detection community primarily focuses on registry queries targeting security-related keys, software enumeration, and reconnaissance patterns that indicate system profiling behavior.

## What This Dataset Contains

This dataset captures a complete registry enumeration attack chain executed via PowerShell. The core evidence includes:

**Process Creation Chain (Security 4688 & Sysmon EID 1):**
- PowerShell spawning `whoami.exe` for user discovery: `"C:\Windows\system32\whoami.exe"`
- PowerShell launching cmd.exe: `"cmd.exe" /c reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64`
- cmd.exe executing the actual registry query: `reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64`

**Registry Query Evidence:** The reg.exe process (PID 5864) exits with status code 0x1, indicating the queried registry key likely doesn't exist or access was denied.

**PowerShell Activity:** Sysmon captures PowerShell.NET runtime loading (mscoree.dll, mscoreei.dll, clr.dll, System.Management.Automation.ni.dll) showing PowerShell execution, though PowerShell script block logging only contains test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass).

**Process Access Events (Sysmon EID 10):** PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process injection detection capabilities.

## What This Dataset Does Not Contain

The dataset lacks several important detection opportunities:

**No Registry Access Logging:** Windows Object Access auditing is disabled, so there are no Security 4656/4663 events showing the actual registry key access attempts that would provide direct evidence of the T1012 technique.

**Limited PowerShell Telemetry:** Script block logging only captures Set-ExecutionPolicy commands rather than the actual Invoke-Expression or registry query commands, suggesting the technique was executed through .NET methods rather than PowerShell cmdlets.

**No Network Activity:** Sysmon shows no DNS queries or network connections, indicating this was purely local system discovery.

**Missing File System Activity:** Beyond PowerShell profile creation, there's minimal file system interaction captured.

## Assessment

This dataset provides moderate value for T1012 detection engineering. While it successfully captures the process execution chain and command-line evidence of registry queries, the lack of registry access auditing significantly limits direct technique detection. The Security 4688 events with full command-line logging provide the strongest detection signal, clearly showing the registry query attempt against the SIL configuration key.

The reg.exe exit code of 0x1 suggests the query failed, which is typical when targeting non-existent registry keys or when access is restricted. This failure mode is actually valuable for detection as it represents realistic attacker reconnaissance that encounters system hardening.

For comprehensive T1012 detection, this dataset would benefit from enabled Object Access auditing for registry operations, which would provide Security events 4656/4663 showing the actual registry key access attempts.

## Detection Opportunities Present in This Data

1. **Registry Query Command Line Detection** - Security 4688 events showing reg.exe execution with HKLM software enumeration patterns: `reg.exe query hklm\software\microsoft\windows\softwareinventorylogging`

2. **PowerShell-to-Registry Chain Detection** - Process tree analysis showing powershell.exe → cmd.exe → reg.exe execution sequence within short time windows

3. **Software Inventory Reconnaissance** - Specific targeting of Software Inventory Logging registry keys indicating adversary interest in system monitoring capabilities

4. **Registry Query Tool Spawning** - Sysmon EID 1 events detecting reg.exe execution from non-administrative processes or scripting engines

5. **Failed Registry Access Patterns** - Process exit codes (0x1) indicating failed registry queries, which may represent reconnaissance attempts against hardened systems

6. **PowerShell Process Injection Indicators** - Sysmon EID 10 events showing PowerShell accessing child processes with full access rights, indicating potential process hollowing or injection techniques

7. **System Discovery Activity Clustering** - Temporal correlation of whoami.exe execution followed by registry queries indicating comprehensive system reconnaissance
