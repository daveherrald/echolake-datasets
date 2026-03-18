# T1057-5: Process Discovery — Process Discovery - wmic process

## Technique Context

T1057 (Process Discovery) is a fundamental Discovery technique where adversaries enumerate running processes to understand system activity, identify security tools, and locate targets for further exploitation. Process discovery is often one of the first post-exploitation activities, helping attackers map the environment and plan subsequent actions.

The detection community focuses heavily on process enumeration activities because they're reliable indicators of reconnaissance behavior. While legitimate system administration involves process discovery, the tooling, frequency, and context often distinguish malicious from benign activity. WMI Command-line (WMIC) is particularly interesting to defenders because it's a powerful LOLBin that provides extensive system information through Windows Management Instrumentation, and its use for process enumeration is a common adversary technique.

## What This Dataset Contains

This dataset captures a clean execution of `wmic process get /format:list` executed through PowerShell. The core telemetry shows the expected process chain:

- **Security 4688 events** capture the full process creation chain: `powershell.exe` → `cmd.exe /c wmic process get /format:list` → `wmic process get /format:list`
- **Sysmon Process Create (EID 1)** events show process creation for both `whoami.exe` (PID 9164) and `cmd.exe` (PID 10812) with full command lines, but notably no ProcessCreate event for the WMIC.exe process itself
- **Sysmon ProcessAccess (EID 10)** events show PowerShell accessing both the whoami and cmd processes with full access rights (0x1FFFFF)
- **Sysmon ImageLoad (EID 7)** events capture WMIC.exe (PID 9620) loading WMI-related DLLs including `wmiutils.dll`, `amsi.dll`, and Windows Defender components
- **Security 4703 events** show token privilege adjustments for both PowerShell and WMIC processes, with WMIC receiving extensive system privileges including SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege

The command line evidence clearly shows the process discovery intent: `"cmd.exe" /c wmic process get /format:list` and `wmic process get /format:list`.

## What This Dataset Does Not Contain

The dataset has a notable gap: while Security 4688 shows WMIC.exe process creation, there's no corresponding Sysmon Process Create (EID 1) event for WMIC.exe. This is because the sysmon-modular configuration uses include-mode filtering for ProcessCreate events, and WMIC.exe appears to not match the known-suspicious patterns in the filter. This demonstrates a limitation of filtered Sysmon configurations where legitimate system tools used maliciously may not generate ProcessCreate telemetry.

The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual process discovery commands, indicating the technique was executed via direct command-line invocation rather than PowerShell scripting.

There's no evidence of the actual process enumeration output or any subsequent actions based on the discovered processes, as this test focuses purely on the discovery technique execution.

## Assessment

This dataset provides good coverage for detecting WMIC-based process discovery through multiple complementary data sources. The Security 4688 events offer complete process chain visibility with command lines, while Sysmon adds behavioral context through ProcessAccess, ImageLoad, and privilege adjustment events. The privilege escalation telemetry (Security 4703) is particularly valuable, as WMIC requesting extensive system privileges is a strong indicator of potentially suspicious activity.

However, the missing Sysmon ProcessCreate event for WMIC.exe highlights the importance of using Security 4688 as the primary source for process creation detection, with Sysmon ProcessCreate as supplementary context rather than the primary detection mechanism.

## Detection Opportunities Present in This Data

1. **WMIC Process Discovery Command Line** - Security 4688 events showing command lines containing "wmic" and "process get" with various format options
2. **WMIC Privilege Elevation** - Security 4703 events showing WMIC.exe requesting extensive system privileges (SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege)
3. **WMI DLL Loading Patterns** - Sysmon EID 7 showing WMIC.exe loading wmiutils.dll and other WMI-related libraries
4. **PowerShell-to-CMD-to-WMIC Process Chain** - Process creation chain analysis showing PowerShell spawning cmd.exe which spawns WMIC for process enumeration
5. **AMSI Integration in WMIC** - Sysmon EID 7 showing WMIC.exe loading amsi.dll, indicating Windows Defender's behavioral monitoring of WMI operations
6. **Cross-Process Access from PowerShell** - Sysmon EID 10 showing PowerShell accessing child processes with full permissions, indicating process manipulation capabilities
