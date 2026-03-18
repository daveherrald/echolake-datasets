# T1047-2: Windows Management Instrumentation — WMI Reconnaissance Processes

## Technique Context

T1047 (Windows Management Instrumentation) is a core execution technique where attackers leverage WMI to run commands, query system information, and execute code remotely. WMI provides extensive system administration capabilities through WQL queries and method invocations, making it valuable for both legitimate administration and malicious activities. This specific test demonstrates WMI reconnaissance, using WMIC to enumerate running processes—a common discovery technique that helps attackers understand the target environment and identify security tools, running applications, or potential privilege escalation opportunities.

Detection engineers focus on WMIC process creation with reconnaissance-oriented arguments, WMI service activity, and the characteristic process chains (PowerShell → cmd → wmic). The community emphasizes monitoring for WQL queries targeting sensitive WMI classes like Win32_Process, especially when combined with format specifications that structure output for programmatic consumption.

## What This Dataset Contains

This dataset captures a successful WMI reconnaissance execution through the process chain: `powershell.exe` → `cmd.exe /c wmic process get caption,executablepath,commandline /format:csv` → `wmic process get caption,executablepath,commandline /format:csv`. 

Key telemetry includes Security EID 4688 events showing the complete command lines: `"cmd.exe" /c wmic process get caption,executablepath,commandline /format:csv` and `wmic process get caption,executablepath,commandline /format:csv`. Sysmon EID 1 events capture the same process creations with Sysmon rule names linking to T1059.003 (Windows Command Shell) and system owner/user discovery (T1033 for whoami.exe execution).

The dataset shows WMIC loading WMI-related DLLs including `C:\Windows\System32\wbem\wmiutils.dll` (EID 7, tagged with T1047 rule name) and security-sensitive components like `amsi.dll` for Anti-Malware Scan Interface integration. Security EID 4703 events document privilege adjustments for both PowerShell and WMIC processes, showing extensive system-level privileges being enabled.

Process access events (Sysmon EID 10) show PowerShell accessing both the spawned cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), indicating potential process injection monitoring that detected the parent-child relationships.

## What This Dataset Does Not Contain

The dataset lacks WMI-specific event logs from the Microsoft-Windows-WMI-Activity channel, which would show WQL query execution details, WMI provider interactions, and the actual reconnaissance data collected. This is a significant gap since WMI operational telemetry often provides the clearest evidence of malicious WMI usage patterns.

Missing are any WMI consumer registrations, WMI event subscriptions, or persistence-related WMI artifacts that more advanced T1047 implementations might create. The sysmon-modular configuration's include-mode filtering means we may have missed process creations that don't match suspicious patterns, though the core technique processes are captured.

Network connections from WMI operations aren't visible, so remote WMI scenarios wouldn't be fully represented. The dataset also doesn't show the actual output or results of the WMI query, which security teams often analyze to understand attacker intent and information gathered.

## Assessment

This dataset provides solid process execution telemetry for WMI reconnaissance detection, with excellent command-line visibility through Security 4688 events and good process relationship tracking through Sysmon. The privilege adjustment logging adds valuable context about the security posture of WMI operations.

However, the absence of WMI-specific operational logs significantly limits its utility for comprehensive WMI detection engineering. WMI Activity logs are crucial for detecting sophisticated WMI abuse, query analysis, and distinguishing malicious from legitimate administrative WMI usage. The dataset is most valuable for process-based detections rather than WMI-behavior-specific analytics.

## Detection Opportunities Present in This Data

1. **WMIC reconnaissance command lines** - Security 4688 and Sysmon 1 events with command lines containing `wmic process get` with multiple sensitive fields like `caption,executablepath,commandline`

2. **WMI process chain analysis** - PowerShell spawning cmd.exe spawning wmic.exe within short timeframes, indicating programmatic WMI usage rather than interactive administration

3. **WMIC CSV output formatting** - Command lines specifying `/format:csv` suggest automated parsing of WMI query results, uncommon in legitimate administration

4. **Concurrent system discovery activities** - whoami.exe execution in temporal proximity to WMI reconnaissance, indicating broader discovery phase activities

5. **WMI DLL loading patterns** - Image load events showing wmiutils.dll and other WMI components loaded by processes not typically associated with WMI administration

6. **Excessive privilege usage in WMI context** - Security 4703 events showing broad privilege enablement (SeBackupPrivilege, SeSecurityPrivilege, etc.) for WMIC processes

7. **Process access patterns from WMI parents** - Sysmon 10 events showing PowerShell accessing spawned WMI-related processes with full access rights, potentially indicating injection or monitoring activities
