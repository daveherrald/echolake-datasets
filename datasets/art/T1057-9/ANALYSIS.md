# T1057-9: Process Discovery — Launch Taskmgr from cmd to View running processes

## Technique Context

T1057 Process Discovery is a common reconnaissance technique where adversaries enumerate running processes on a system to understand what applications, security tools, or services are active. This information helps attackers identify targets for privilege escalation, defensive tool evasion, or lateral movement opportunities. The technique is frequently observed in both automated malware and manual threat actor operations.

Detection engineering teams typically focus on unusual process enumeration patterns, command-line tools being used for discovery (tasklist, wmic, Get-Process), or GUI applications like Task Manager being launched programmatically. This particular test simulates launching Task Manager via command line with the `/7` parameter, which forces the detailed view showing additional process information.

## What This Dataset Contains

This dataset captures the complete execution chain of launching Task Manager from PowerShell via cmd.exe:

**Process Chain:** PowerShell → cmd.exe → taskmgr.exe (with crash and restart)
- Security EID 4688: `"cmd.exe" /c taskmgr.exe /7` (PID 0x3e10)
- Security EID 4688: `taskmgr.exe /7` (PID 0x3964) 
- Security EID 4688: Second instance `taskmgr.exe /7` (PID 0x394c)
- Sysmon EID 1: cmd.exe creation with full command line `"cmd.exe" /c taskmgr.exe /7`

**Task Manager Crash Events:**
- Application EIDs 1000/1001: Task Manager crash with exception code 0xc0000409 in dcomp.dll
- Security EID 4689: Taskmgr.exe exit with status 0xC0000409
- Security EID 4689: cmd.exe exit with status 0xC0000409

**Windows Error Reporting Activity:**
- Sysmon EID 1: WerFault.exe processes for crash reporting
- Sysmon EID 10: Process access events showing WerFault accessing the crashed Taskmgr process with PROCESS_ALL_ACCESS (0x1FFFFF)

**Supporting Telemetry:**
- Sysmon EID 7: DLL loads in PowerShell including System.Management.Automation
- PowerShell channel: Only contains test framework boilerplate (Set-ExecutionPolicy Bypass, Set-StrictMode)
- Security EID 4703: Token privilege adjustment for PowerShell process

## What This Dataset Does Not Contain

The dataset lacks evidence of successful process discovery because Task Manager crashed immediately after launch. There are no network connections, file system enumeration, or registry queries that would typically accompany successful process discovery operations. The Sysmon config's include-mode filtering means we don't see Sysmon ProcessCreate events for the taskmgr.exe instances, though Security 4688 events provide full coverage.

The crash appears to be environmental (dcomp.dll exception) rather than defensive tool interference, as there are no access denied errors or Defender blocking signatures. The `/7` parameter usage, which should force detailed view mode, cannot be validated since the application crashed before completing initialization.

## Assessment

This dataset provides excellent telemetry for detecting programmatic Task Manager launches via the distinctive command line pattern, but limited value for understanding successful process discovery behavior due to the application crash. The Security 4688 events with command-line logging are the primary detection data source, complemented by Sysmon process creation events for the command shell execution.

The crash artifacts actually add detection value by showing how application failures can generate additional telemetry through Windows Error Reporting, including process access events that might otherwise indicate credential dumping attempts. This demonstrates the importance of understanding normal vs. abnormal application behavior in detection engineering.

## Detection Opportunities Present in This Data

1. **Programmatic Task Manager Launch** - Security EID 4688 with command line containing "taskmgr.exe" launched from cmd.exe or PowerShell rather than interactive user sessions

2. **Task Manager with Parameters** - Command lines containing "taskmgr.exe /7" or other command-line parameters, which is unusual for normal user behavior

3. **Process Chain Analysis** - PowerShell → cmd.exe → taskmgr.exe execution chains, especially when PowerShell is the initial parent process

4. **Rapid Process Creation/Termination** - Task Manager processes that exit quickly with error codes (0xC0000409) potentially indicating automated discovery attempts

5. **Windows Error Reporting Process Access** - Sysmon EID 10 showing WerFault.exe accessing crashed processes with full access rights, which can mask legitimate process dumping attempts

6. **Command Shell Process Discovery Pattern** - cmd.exe processes with `/c` parameter launching system utilities commonly used for reconnaissance
