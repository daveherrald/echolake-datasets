# T1124-2: System Time Discovery — System Time Discovery - PowerShell

## Technique Context

T1124 System Time Discovery involves adversaries gathering information about the system time and timezone configuration. This technique is commonly used during reconnaissance phases to understand the target environment, coordinate time-sensitive operations, or determine if the target system is in a sandbox environment (which often has unrealistic time settings). Attackers frequently use this technique alongside other discovery techniques to build a comprehensive picture of the target system.

The detection community focuses on identifying unexpected time queries, especially those executed via PowerShell, command line utilities, or API calls that retrieve system time information. While legitimate system administration tasks regularly query time, the context and frequency of these queries can indicate malicious reconnaissance activity.

## What This Dataset Contains

This dataset captures the execution of PowerShell's `Get-Date` cmdlet for system time discovery. The telemetry shows:

**Security Event 4688**: Process creation for `"powershell.exe" & {Get-Date}` (Process ID 0xa338/41784), created by parent PowerShell process 0xa2ac/41644.

**PowerShell Script Block Logging (EID 4104)**: Multiple script block creation events showing the execution sequence:
- `& {Get-Date}` in script block ID d3276a83-d66b-4dc3-ab17-2b84e9a2117b
- `{Get-Date}` in script block ID 966f0968-8cae-49e9-97fc-ad15e0d34cd6
- Various PowerShell framework boilerplate script blocks with `Set-StrictMode` commands

**PowerShell Command Invocation (EID 4103)**: Direct evidence of the technique execution with `CommandInvocation(Get-Date): "Get-Date"` showing the command was successfully invoked by ACME\SYSTEM user.

**Sysmon Process Creation (EID 1)**: Two PowerShell process creations captured:
- Parent process: `powershell.exe` (PID 41644)  
- Child process: `"powershell.exe" & {Get-Date}` (PID 41784)

**Sysmon Image Loads (EID 7)**: Extensive .NET Framework DLL loading for PowerShell execution, including System.Management.Automation.ni.dll, demonstrating the PowerShell engine initialization.

## What This Dataset Does Not Contain

The dataset lacks Security Event 4688 process creation events for the initial parent PowerShell process, likely due to the sysmon-modular configuration's include-mode filtering that only captures processes matching suspicious patterns. The parent PowerShell process creation may not have triggered the include rules.

No Sysmon ProcessCreate (EID 1) event exists for the parent PowerShell process for the same filtering reason. The child PowerShell process with the `Get-Date` command was captured because it matches PowerShell execution patterns in the include rules.

The dataset contains no network activity, file system modifications beyond PowerShell profile data, or registry changes, as this technique only queries system time without persistence or external communication.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based system time discovery. The combination of Security 4688 process creation with command-line logging, PowerShell script block logging (4104), and command invocation logging (4103) creates multiple detection opportunities. The Sysmon telemetry adds process relationship context and detailed image loading behavior.

The PowerShell logging is particularly valuable, capturing both the script block content and command invocation details that clearly show the `Get-Date` cmdlet execution. This level of detail enables detection engineers to distinguish between legitimate administrative time queries and potential reconnaissance activity based on context and frequency.

## Detection Opportunities Present in This Data

1. **PowerShell Get-Date Command Invocation**: Monitor PowerShell EID 4103 events for `CommandInvocation(Get-Date)` to detect time discovery attempts via PowerShell cmdlets.

2. **PowerShell Script Block with Time Discovery**: Alert on PowerShell EID 4104 script block events containing `Get-Date` cmdlet executions, especially when occurring alongside other discovery activities.

3. **Process Creation with Get-Date Command Line**: Monitor Security EID 4688 for PowerShell process creation with command lines containing `Get-Date` or similar time discovery patterns.

4. **PowerShell Process Chains for Discovery**: Use Sysmon EID 1 to track PowerShell parent-child process relationships where child processes execute discovery commands like `Get-Date`.

5. **Bulk Discovery Activity Correlation**: Correlate multiple discovery technique executions (time, user, system info) within short time windows to identify reconnaissance phases.

6. **PowerShell Time Discovery from Unexpected Users**: Monitor for `Get-Date` executions from service accounts or users who don't typically perform administrative time queries.
