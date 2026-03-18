# T1082-38: System Information Discovery — Enumerate Available Drives via gdr

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries gather information about the victim system to understand its configuration, installed software, and available resources. The "gdr" command specifically refers to PowerShell's Get-PSDrive (alias "gdr") cmdlet, which enumerates PowerShell drives including file system drives, registry hives, and other provider-mapped drives. This technique is commonly used by attackers during initial system profiling to map available storage locations, understand system architecture, and identify potential targets for data exfiltration or lateral movement. Detection engineers focus on identifying unusual PowerShell discovery commands, especially when executed in rapid succession or from unexpected contexts like scheduled tasks or service accounts.

## What This Dataset Contains

This dataset captures a PowerShell-based drive enumeration execution with the command line `gdr -PSProvider 'FileSystem'`. The Security channel shows the complete process chain: a PowerShell parent process (PID 41116) spawning cmd.exe (PID 11248) with command line `"cmd.exe" /c powershell.exe -c "gdr -PSProvider 'FileSystem'"`, which then creates the child PowerShell process (PID 12140) that executes the actual discovery command. 

The PowerShell operational logs contain the technique evidence with EID 4103 showing `CommandInvocation(Get-PSDrive): "Get-PSDrive"` with parameter binding `name="PSProvider"; value="FileSystem"`. Additional PowerShell events show multiple CIM-related operations including `CommandInvocation(Get-CimInstance): "Get-CimInstance"` with parameters `name="Filter"; value="DeviceId='C:'"` and `name="ClassName"; value="Win32_LogicalDisk"`, indicating the command also performed WMI queries for disk information.

Sysmon captures the full process tree with EID 1 events showing the cmd.exe creation with rule name "technique_id=T1059.003,technique_name=Windows Command Shell" and the PowerShell process creation tagged as "technique_id=T1059.001,technique_name=PowerShell". The dataset also includes normal .NET runtime loading events (EID 7) for the PowerShell processes.

## What This Dataset Does Not Contain

The dataset lacks any evidence of the actual command output or results from the drive enumeration. While we see the PowerShell command execution and WMI queries, there are no events showing what drives were discovered or how that information was used. Additionally, there are no network connections, file access patterns, or subsequent discovery commands that might indicate how an attacker would leverage this information. The technique executed successfully without any blocking from Windows Defender, as evidenced by the clean exit status 0x0 in the Security 4689 events.

## Assessment

This dataset provides solid coverage for detecting PowerShell-based system discovery activity. The combination of Security 4688/4689 events with full command lines, PowerShell operational logging showing both the Get-PSDrive cmdlet and underlying CIM operations, and Sysmon process creation events creates multiple detection opportunities. The process chain is clearly visible across all three data sources, making this valuable for correlation-based detections. However, the dataset would be stronger with evidence of output handling or follow-on activities that would typically occur after system enumeration.

## Detection Opportunities Present in This Data

1. **PowerShell Get-PSDrive cmdlet execution** - PowerShell EID 4103 CommandInvocation events for Get-PSDrive with PSProvider parameter filtering for FileSystem drives
2. **Suspicious process chain pattern** - Security EID 4688 showing PowerShell spawning cmd.exe which then spawns another PowerShell instance for single command execution
3. **PowerShell one-liner execution pattern** - Command line pattern `powershell.exe -c "gdr -PSProvider 'FileSystem'"` indicating scripted discovery activity
4. **WMI Win32_LogicalDisk queries** - PowerShell EID 4103 showing Get-CimInstance operations against Win32_LogicalDisk class with DeviceId filtering
5. **System account PowerShell discovery** - PowerShell discovery commands executed under NT AUTHORITY\SYSTEM context, unusual for legitimate administrative tasks
6. **Rapid PowerShell module/cmdlet loading** - Sysmon EID 7 showing System.Management.Automation.ni.dll loading followed immediately by discovery cmdlets
