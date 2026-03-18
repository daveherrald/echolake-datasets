# T1047-4: Windows Management Instrumentation — WMI Reconnaissance List Remote Services

## Technique Context

T1047 (Windows Management Instrumentation) is a foundational technique for system administration and adversary operations on Windows. WMI provides a standardized interface for querying system information, managing processes, and executing commands both locally and remotely. Attackers frequently leverage WMI for reconnaissance activities such as enumerating services, processes, user accounts, and network configurations. The technique is particularly valuable because it uses legitimate Windows administrative tools, making detection challenging without proper behavioral analysis.

This specific test (T1047-4) focuses on the reconnaissance aspect of WMI usage, specifically querying remote services using WMIC to search for services containing "Spooler" in their caption. The detection community typically focuses on command-line patterns, process execution chains, WMI query content, and the combination of reconnaissance commands executed in sequence.

## What This Dataset Contains

The dataset captures a complete WMI reconnaissance execution chain with excellent telemetry across multiple data sources:

**Process Execution Chain (Security 4688):**
- PowerShell spawning: `powershell.exe`
- Target discovery execution: `"C:\Windows\system32\whoami.exe"`
- WMI command execution: `"cmd.exe" /c wmic /node:"127.0.0.1" service where (caption like "%Spooler%")`
- WMIC process: `wmic  /node:"127.0.0.1" service where (caption like "%Spooler%")`

**Sysmon Process Creation (EID 1):**
- Whoami execution with full command line and process metadata
- Cmd.exe spawning with the complete WMIC command revealing the reconnaissance target
- Process GUIDs linking the execution chain from PowerShell through cmd.exe to WMIC

**WMI-Specific Telemetry (Sysmon EID 7):**
- WMIC.exe loading WMI-related DLLs: `wmiutils.dll` tagged with `technique_id=T1047,technique_name=Windows Management Instrumentation`
- VBScript.dll loading indicating WMI query processing
- AMSI.dll loading showing anti-malware scanning integration

**Privilege Usage (Security 4703):**
- Token privilege adjustments for both PowerShell and WMIC processes, including `SeBackupPrivilege`, `SeRestorePrivilege`, and other sensitive privileges

The command line clearly shows remote WMI querying (`/node:"127.0.0.1"`) with service enumeration targeting the Print Spooler service, a common reconnaissance pattern.

## What This Dataset Does Not Contain

**Network Activity:** No Sysmon network connection events (EID 3) are present, likely because the query targeted localhost (127.0.0.1) rather than generating actual network traffic.

**WMI Event Channel:** The dataset lacks events from the Microsoft-Windows-WMI-Activity/Operational channel, which would provide detailed WMI query execution details and could show the actual WQL query structure.

**PowerShell Script Content:** The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual WMI reconnaissance commands, indicating the technique was likely executed through direct command invocation rather than PowerShell WMI cmdlets.

**Service Query Results:** No evidence of the actual query output or results from the WMI service enumeration.

## Assessment

This dataset provides strong detection engineering value for WMI reconnaissance activities. The combination of Security 4688 and Sysmon EID 1 events captures the complete process execution chain with full command-line visibility, making it excellent for developing command-line pattern detection rules. The Sysmon EID 7 events specifically tagged with T1047 provide clear indicators of WMI library loading.

The telemetry effectively demonstrates how legitimate administrative tools (WMIC) can be used for reconnaissance purposes, with clear process lineage from PowerShell through cmd.exe to WMIC. The privilege adjustment events (Security 4703) add additional detection opportunities by showing elevated privilege usage patterns.

The primary limitation is the lack of WMI-specific event channels, but the process-level telemetry compensates well for basic detection engineering needs. This dataset would be significantly enhanced by including WMI-Activity channel events for more granular WMI query analysis.

## Detection Opportunities Present in This Data

1. **WMIC Command Line Pattern Detection** - Security 4688 and Sysmon EID 1 events show `wmic` with `/node:` parameter and service enumeration syntax, indicating remote WMI reconnaissance

2. **Process Chain Analysis** - PowerShell spawning cmd.exe spawning wmic.exe with reconnaissance-focused command lines indicates potential adversary toolchain usage

3. **WMI Library Loading** - Sysmon EID 7 events showing WMIC.exe loading `wmiutils.dll` tagged with T1047 technique provide library-level WMI usage indicators

4. **Privilege Escalation Context** - Security 4703 token privilege adjustments for WMIC processes using sensitive privileges like `SeBackupPrivilege` and `SeRestorePrivilege`

5. **Service Reconnaissance Pattern** - Command line containing `service where (caption like "%Spooler%")` indicates specific service enumeration targeting Print Spooler

6. **Localhost Targeting** - The `/node:"127.0.0.1"` parameter pattern may indicate local system reconnaissance or testing before targeting remote systems

7. **Process Access Monitoring** - Sysmon EID 10 events show PowerShell accessing spawned processes with full access rights (0x1FFFFF), indicating process management activities

8. **Execution Context Analysis** - All processes executing under NT AUTHORITY\SYSTEM context with specific LogonId patterns provide execution environment indicators
