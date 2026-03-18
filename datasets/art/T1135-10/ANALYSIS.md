# T1135-10: Network Share Discovery — Network Share Discovery via dir command

## Technique Context

T1135 (Network Share Discovery) focuses on adversary attempts to enumerate network shares on local and remote systems. This is a fundamental discovery technique used early in the attack lifecycle to understand what resources are accessible and potentially identify high-value targets like file servers or administrative shares. Attackers commonly use built-in Windows utilities like `dir`, `net view`, `net use`, or PowerShell cmdlets to enumerate shares. The detection community focuses on monitoring command-line activity for share enumeration patterns, particularly targeting administrative shares (C$, ADMIN$, IPC$) or using UNC paths with wildcards.

## What This Dataset Contains

This dataset captures a straightforward network share discovery attempt using the Windows `dir` command to enumerate administrative shares on the localhost. The core technique execution appears in Security event 4688 with the command line: `"cmd.exe" /c dir \\127.0.0.1\c$ & dir \\127.0.0.1\admin$ & dir \\127.0.0.1\IPC$`. 

The process chain shows PowerShell (PID 11576) spawning cmd.exe (PID 44444) to execute the share enumeration commands. Sysmon captures this as ProcessCreate event (EID 1) with rule name `technique_id=T1083,technique_name=File and Directory Discovery`, demonstrating how share discovery overlaps with file system discovery techniques.

Additional telemetry includes PowerShell startup activities with .NET framework loading (multiple EID 7 events), pipe creation for PowerShell host communication (EID 17), and process termination events (Security EID 4689) showing cmd.exe exiting with status 0x1, indicating the commands likely failed due to access restrictions or share unavailability.

## What This Dataset Does Not Contain

The dataset lacks network-level telemetry that would show actual SMB connection attempts to the enumerated shares. While we see the command execution, there are no Sysmon network connection events (EID 3) that would indicate successful or failed SMB connections to \\127.0.0.1. This suggests either the technique failed before network activity occurred, or the sysmon-modular configuration doesn't capture localhost SMB connections.

Missing are any authentication-related events (Security EID 4624/4625) that would typically accompany successful or failed share access attempts. The dataset also doesn't contain any object access events that would show successful enumeration of share contents, indicating the discovery attempt was unsuccessful.

## Assessment

This dataset provides excellent process-level telemetry for network share discovery detection engineering. The Security channel's process creation logging with full command-line capture (EID 4688) provides the most valuable detection data, clearly showing the share enumeration syntax. The Sysmon ProcessCreate events complement this with parent-child process relationships and file hashes.

However, the dataset's utility is somewhat limited by the apparent failure of the technique to generate network traffic or successful enumeration results. For comprehensive detection development, analysts would benefit from datasets showing both successful and failed share enumeration attempts with corresponding network and authentication telemetry.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security EID 4688 with command lines containing `dir \\` followed by administrative share names (C$, ADMIN$, IPC$)

2. **Administrative share targeting** - Specific detection for commands attempting to access default Windows administrative shares using UNC paths

3. **Process ancestry analysis** - PowerShell spawning cmd.exe for network discovery activities, detectable through parent-child process relationships in Sysmon EID 1

4. **Batch command chaining** - Multiple share enumeration commands chained with `&` operators in a single command execution

5. **Localhost share enumeration** - Specific pattern of using 127.0.0.1 or localhost for initial share discovery reconnaissance

6. **PowerShell-initiated system discovery** - Correlation between PowerShell process startup and subsequent system/network discovery commands within short time windows
