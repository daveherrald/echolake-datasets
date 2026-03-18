# T1222-1: File and Directory Permissions Modification — Enable Local and Remote Symbolic Links via fsutil

## Technique Context

T1222 - File and Directory Permissions Modification represents adversaries' attempts to modify file or directory permissions/attributes to evade access controls or hide malicious activity. This specific test (T1222-1) focuses on enabling symbolic link evaluation through `fsutil`, a Windows file system utility. Symbolic links can be abused by attackers to bypass security controls, redirect file access to malicious locations, or escalate privileges by manipulating file system references. The technique is particularly relevant in defense evasion scenarios where attackers need to circumvent file system protections or create deceptive file structures. Detection teams typically focus on monitoring `fsutil` usage, especially commands that modify symbolic link behavior, as these operations are rarely performed by legitimate users and often indicate malicious intent.

## What This Dataset Contains

The dataset captures a successful execution of `fsutil` commands to enable symbolic link evaluation. The primary evidence appears in Security event 4688 showing the command execution: `"cmd.exe" /c fsutil behavior set SymlinkEvaluation R2L:1 & fsutil behavior set SymlinkEvaluation R2R:1`. This command enables both remote-to-local (R2L) and remote-to-remote (R2R) symbolic link evaluation.

The complete process chain is visible across multiple data sources:
- PowerShell (PID 37184) spawns cmd.exe (PID 34192) 
- cmd.exe executes two sequential fsutil commands (PIDs 25460 and 33164)
- Both fsutil processes exit with status 0x0, indicating successful execution

Sysmon EID 1 events capture the process creation for cmd.exe with the full command line, and both fsutil executions with their specific arguments. The process access events (EID 10) show PowerShell accessing both the cmd.exe and fsutil processes, typical of parent-child process relationships. Security events 4688/4689 provide complementary process creation and termination telemetry with exit codes confirming successful execution.

## What This Dataset Does Not Contain

The dataset lacks registry modification events that would typically accompany symbolic link behavior changes. While `fsutil behavior set` commands modify system behavior, the specific registry writes to HKLM\SYSTEM\CurrentControlSet\Control\FileSystem are not captured, likely because Sysmon's configuration doesn't monitor registry modifications or these specific registry keys aren't in scope.

There's no evidence of the actual symbolic links being created or used after enabling the evaluation - this test only modifies the system's willingness to evaluate symbolic links rather than creating malicious links. File system monitoring events that would show symbolic link creation, access, or exploitation are absent. Additionally, any potential security log entries related to privilege escalation or access control modifications beyond the process creation events are not present.

## Assessment

This dataset provides excellent detection opportunities for the specific technique of enabling symbolic link evaluation via fsutil. The command-line logging in Security 4688 events captures the exact commands with clear indicators of malicious intent. Sysmon process creation events provide additional context and timing information. However, the dataset would be more valuable if it included the subsequent registry changes and any follow-up symbolic link activity that might occur in a real attack scenario. The telemetry present is sufficient for detecting this specific preparatory action but doesn't show the complete attack chain that would typically follow.

## Detection Opportunities Present in This Data

1. **fsutil symbolic link modification detection** - Security EID 4688 with command line containing `fsutil behavior set SymlinkEvaluation` with R2L or R2R parameters
2. **Suspicious cmd.exe usage patterns** - Command execution combining multiple fsutil commands in a single line using ampersand concatenation 
3. **PowerShell spawning system utilities** - Sysmon EID 1 showing powershell.exe as parent of cmd.exe executing file system modification commands
4. **Administrative tool abuse** - Process creation of fsutil.exe with behavior modification arguments, particularly when spawned from scripting engines
5. **Process chain analysis** - Sequential execution pattern of PowerShell → cmd.exe → fsutil.exe for system configuration changes
6. **Command line pattern matching** - Security events containing "SymlinkEvaluation" parameter modifications, especially enabling remote symbolic link evaluation
