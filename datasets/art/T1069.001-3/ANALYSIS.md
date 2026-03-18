# T1069.001-3: Local Groups — Permission Groups Discovery PowerShell (Local)

## Technique Context

T1069.001 (Permission Groups Discovery: Local Groups) is a Discovery technique where attackers enumerate local security groups to understand privilege escalation paths and identify high-value accounts. This is fundamental reconnaissance that helps attackers map the local security landscape before attempting lateral movement or privilege escalation. The technique is commonly implemented using PowerShell cmdlets like `Get-LocalGroup` and `Get-LocalGroupMember`, Windows `net` commands, or direct Windows API calls. Detection communities typically focus on monitoring PowerShell cmdlet invocations, command-line patterns, and API calls to local security account manager (SAM) functions. This technique generates relatively little noise in most environments, making it an attractive early-stage reconnaissance method for attackers.

## What This Dataset Contains

This dataset captures a PowerShell-based local group enumeration executed via Atomic Red Team. The core technique evidence appears in the PowerShell channel, where EID 4103 events show the execution of `Get-LocalGroup` and `Get-LocalGroupMember -Name "Administrators"` cmdlets. The Security channel captures the full process chain with EID 4688 events showing the parent PowerShell process (PID 0x6e1c) spawning a child PowerShell process (PID 0x6ba4) with the command line `"powershell.exe" & {get-localgroup\nGet-LocalGroupMember -Name \"Administrators\"}`. Sysmon provides complementary telemetry with EID 1 ProcessCreate events for both the `whoami.exe` execution and the child PowerShell process, plus extensive EID 7 ImageLoaded events showing the .NET runtime and PowerShell automation DLL loading patterns. The dataset also contains EID 10 ProcessAccessed events showing PowerShell accessing child processes, and EID 17 PipeCreated events for PowerShell inter-process communication.

## What This Dataset Does Not Contain

The PowerShell script block logging (EID 4104) primarily contains test framework boilerplate (`Set-StrictMode -Version 1`) rather than the actual discovery commands, which limits visibility into the specific enumeration activities. The dataset lacks the actual output or results from the group enumeration commands, so we don't see what local groups were discovered or which administrators were identified. There are no registry access events that might show alternative methods of group enumeration via direct SAM database queries. Network-related group discovery activities (if any occurred) are not captured, and there's no evidence of follow-on activities that might leverage the discovered group information.

## Assessment

This dataset provides good coverage of PowerShell-based local group enumeration from multiple complementary data sources. The Security channel's process creation events with command-line logging offer the strongest detection signal, clearly showing the suspicious PowerShell command execution. Sysmon ProcessCreate events provide additional process genealogy context, though they're filtered by the include-mode configuration. The PowerShell operational channel captures the cmdlet invocations directly, which is valuable for detecting this technique even when command-line logging might be disabled. However, the limited PowerShell script block content reduces the dataset's value for understanding the full scope of enumeration activities. Overall, this represents a solid baseline for detecting PowerShell-based local group discovery, particularly valuable for environments with comprehensive logging.

## Detection Opportunities Present in This Data

1. **PowerShell cmdlet invocation monitoring** - EID 4103 events showing `Get-LocalGroup` and `Get-LocalGroupMember` cmdlet execution with specific parameter bindings like `Name="Administrators"`

2. **Suspicious PowerShell command-line patterns** - Security EID 4688 events with command lines containing local group enumeration patterns like `get-localgroup` and `Get-LocalGroupMember`

3. **PowerShell process spawning behavior** - Parent-child PowerShell process relationships where the child process executes discovery commands, visible in both Security 4688 and Sysmon 1 events

4. **PowerShell automation DLL loading** - Sysmon EID 7 events showing `System.Management.Automation.ni.dll` loading patterns that indicate PowerShell discovery activity

5. **PowerShell named pipe creation** - Sysmon EID 17 events showing PowerShell-specific named pipes like `\PSHost.*powershell` that correlate with discovery command execution

6. **Process access patterns** - Sysmon EID 10 events showing PowerShell processes accessing newly spawned child processes with full access rights (0x1FFFFF)

7. **Token privilege adjustment correlation** - Security EID 4703 events showing privilege escalation concurrent with discovery activities, indicating potential preparation for follow-on attacks
