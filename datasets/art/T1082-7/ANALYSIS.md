# T1082-7: System Information Discovery — Hostname Discovery (Windows)

## Technique Context

T1082 System Information Discovery is a fundamental Discovery tactic technique where adversaries gather information about the operating system and hardware of compromised systems. Hostname discovery specifically focuses on identifying the computer name, which helps attackers understand their position within a network and identify high-value targets. The detection community prioritizes monitoring for reconnaissance commands like `hostname`, `whoami`, and system enumeration utilities, as these often appear in early attack phases and can indicate both automated malware behavior and manual adversary activity.

## What This Dataset Contains

This dataset captures a straightforward execution of the `hostname` command through PowerShell. The Security channel shows the complete process chain in Security event 4688: PowerShell (PID 27628) spawning `cmd.exe /c hostname` (PID 26316). The Sysmon channel provides complementary telemetry with ProcessCreate events showing the same process launches, including the whoami.exe execution (PID 41128) with command line `"C:\Windows\system32\whoami.exe"` and cmd.exe with `"cmd.exe" /c hostname`. 

The dataset also contains extensive PowerShell initialization telemetry across three separate PowerShell instances (PIDs 39980, 27628, 40840), showing .NET framework loading through Sysmon EID 7 events and PowerShell script block creation (EID 4104) events that are primarily test framework boilerplate containing `Set-StrictMode -Version 1` calls. Security EID 4703 shows token privilege adjustment for the PowerShell process, granting extensive system privileges including SeBackupPrivilege and SeRestorePrivilege.

## What This Dataset Does Not Contain

The dataset does not capture the actual output of the `hostname` command, as standard output is not logged by Windows event logging. There are no network connections, file system artifacts beyond PowerShell profile touches, or registry modifications related to the hostname discovery itself. The technique executed successfully with all processes showing exit status 0x0, so there are no blocked execution artifacts or Defender intervention events. The sysmon-modular config's include-mode filtering for ProcessCreate captured both `whoami.exe` and `cmd.exe` due to their status as commonly abused utilities, but may miss other hostname discovery methods using less suspicious binaries.

## Assessment

This dataset provides excellent telemetry for detecting hostname discovery activities. The Security channel's process creation events with command-line logging offer the most reliable detection opportunity, capturing both the execution method (PowerShell -> cmd.exe) and the specific reconnaissance command. Sysmon ProcessCreate events provide additional context and process relationship details. However, the dataset would be stronger with additional hostname discovery variants (direct hostname.exe execution, PowerShell Get-ComputerInfo cmdlet, WMI queries) to demonstrate detection coverage across different techniques.

## Detection Opportunities Present in This Data

1. **Command Line Analysis** - Security EID 4688 and Sysmon EID 1 capturing command lines containing "hostname" executed by cmd.exe or PowerShell processes
2. **Process Chain Analysis** - PowerShell spawning cmd.exe with /c parameter followed by system information commands indicating scripted reconnaissance
3. **Reconnaissance Tool Execution** - Sysmon ProcessCreate events for whoami.exe and cmd.exe with system discovery arguments, tagged with appropriate MITRE technique mappings
4. **Privilege Context Monitoring** - Security EID 4703 showing token privilege adjustments in PowerShell processes that subsequently launch discovery tools
5. **Cross-Channel Correlation** - Combining Security process creation events with Sysmon process access events (EID 10) showing PowerShell accessing discovery tool processes with full access rights (0x1FFFFF)
