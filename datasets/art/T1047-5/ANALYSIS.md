# T1047-5: Windows Management Instrumentation — WMI Execute Local Process

## Technique Context

Windows Management Instrumentation (WMI) is a powerful Windows administration feature that allows querying system information and executing commands locally or remotely. T1047 represents attackers abusing WMI's legitimate process creation capabilities to execute malicious code while potentially evading detection. The technique is particularly valuable because WMI operations can appear as normal administrative activity, making detection challenging.

Attackers commonly use WMI through the `wmic.exe` command-line utility to spawn processes using the `process call create` method. This technique is frequently observed in living-off-the-land attacks, lateral movement scenarios, and persistence mechanisms. The detection community focuses on monitoring WMI process creation events, command-line patterns containing WMI execution syntax, and the characteristic parent-child process relationships where WmiPrvSE.exe spawns the target process.

## What This Dataset Contains

This dataset captures a complete WMI process execution sequence using the command `wmic process call create notepad.exe`. The telemetry shows the full execution chain:

Security Event 4688 captures the process creation hierarchy: PowerShell (PID 32028) → cmd.exe with command line `"cmd.exe" /c wmic process call create notepad.exe` → WMIC.exe (PID 32696) with arguments `wmic process call create notepad.exe`. The final target process notepad.exe (PID 32976) is created with WmiPrvSE.exe as its parent, showing the characteristic WMI execution pattern.

Sysmon Event 1 provides detailed process creation telemetry, including the critical notepad.exe creation event showing `ParentProcessGuid: {9dc7570a-b82a-69b3-8400-000000001000}`, `ParentProcessId: 4844`, and `ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe`. The parent command line shows `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding`, confirming WMI service involvement.

Security Event 4703 shows token privilege adjustments for both WMIC.exe and PowerShell processes, with extensive privilege enablement including `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`, and other high-privilege tokens typical of WMI operations.

Sysmon Events 7 capture DLL loads including Windows Defender integration (MpOAV.dll, MpClient.dll) and AMSI (amsi.dll) loading in WMIC.exe, showing security product monitoring. Sysmon Event 10 shows process access events from PowerShell to both whoami.exe and cmd.exe with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks Sysmon ProcessCreate events for WMIC.exe itself due to the sysmon-modular configuration's include-mode filtering. While Security 4688 captures all process creations, the missing Sysmon Event 1 for WMIC means reduced visibility into detailed process metadata, hashes, and parent process relationships for the WMI utility itself.

No WMI-specific event logs are present (Microsoft-Windows-WMI-Activity/Operational), which would provide additional context about WMI queries, provider interactions, and potential authentication details. The dataset also doesn't contain any network activity, as this test executes entirely locally.

The PowerShell logs contain only execution policy changes and Set-StrictMode boilerplate rather than the actual WMI execution commands, suggesting the technique was invoked through direct command execution rather than PowerShell WMI cmdlets.

## Assessment

This dataset provides excellent telemetry for detecting WMI process execution abuse. The combination of Security 4688 command-line logging and Sysmon process creation events captures the essential behavioral indicators that distinguish malicious WMI usage from legitimate administration. The clear parent-child relationship between cmd.exe → WMIC.exe → WmiPrvSE.exe → target process represents the core detection pattern for this technique.

The privilege escalation events and process access monitoring add valuable context for understanding the elevated permissions required for WMI operations. Windows Defender and AMSI integration visibility demonstrates how security products monitor these operations in real-time environments.

## Detection Opportunities Present in This Data

1. **WMI Process Creation Command Line Detection** - Security 4688 events showing command lines containing `wmic process call create` or `wmic.exe` with `process call create` parameters

2. **Suspicious Parent-Child Process Relationships** - Sysmon Event 1 showing processes with WmiPrvSE.exe as parent, especially for unusual executables or those launched from non-administrative contexts

3. **WMIC.exe Execution Monitoring** - Security 4688 process creation events for C:\Windows\System32\wbem\WMIC.exe, particularly with process manipulation arguments

4. **Token Privilege Escalation Correlation** - Security 4703 events showing extensive privilege enablement (SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege) correlated with WMI process execution

5. **Process Access Pattern Detection** - Sysmon Event 10 showing PowerShell or other scripting engines accessing cmd.exe with full rights (0x1FFFFF) immediately before WMI execution

6. **WMI Service Process Spawning** - Process creation events where the parent is wmiprvse.exe with the `-secured -Embedding` command line, indicating WMI service-mediated execution

7. **Cross-Process Access Before WMI Execution** - Sysmon Event 10 access patterns from scripting hosts to command shells followed by WMI utility execution within short time windows
