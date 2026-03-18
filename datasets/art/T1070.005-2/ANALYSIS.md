# T1070.005-2: Network Share Connection Removal — Remove Network Share

## Technique Context

T1070.005 Network Share Connection Removal is a defense evasion technique where adversaries remove evidence of network share connections to limit forensic evidence and reduce the likelihood of detection. This technique is commonly used by attackers to clean up after lateral movement activities involving network shares, mapped drives, or remote file system access. The detection community focuses on monitoring commands that manage network shares (like `net share`, `net use`, WMI calls, and PowerShell cmdlets), process creation patterns showing cleanup activities, and registry modifications related to network share persistence. This technique often appears in post-exploitation phases as attackers attempt to cover their tracks after establishing persistence or exfiltrating data through network shares.

## What This Dataset Contains

This dataset captures a `net share` deletion command executed through a PowerShell-to-cmd process chain. Security event 4688 shows the full command line: `"cmd.exe" /c net share \\test\share /delete`, spawned from PowerShell process ID 37280. The process chain continues with Security 4688 events showing `net.exe` (PID 38308) executing `net share \\test\share /delete`, which then spawns `net1.exe` (PID 38628) with the same arguments. Sysmon EID 1 events capture the same process creations with additional context, showing the parent-child relationships: powershell.exe → cmd.exe → net.exe → net1.exe. All processes execute with NT AUTHORITY\SYSTEM privileges and exit with status 0x2 (ERROR_FILE_NOT_FOUND), indicating the share `\\test\share` did not exist. Sysmon EID 10 events show process access from PowerShell to both whoami.exe and cmd.exe with full access rights (0x1FFFFF). The dataset also contains standard PowerShell module loading events and Windows Defender DLL loading in the PowerShell process.

## What This Dataset Does Not Contain

This dataset lacks evidence of successful share deletion since the target share `\\test\share` did not exist on the system, resulting in error exit codes rather than successful deletion telemetry. There are no registry modifications related to persistent network share configurations, no network connection events showing active share usage, and no file system events indicating access to actual shared resources. The dataset contains no WMI events that might show alternative methods of share management, no Event ID 5140 (network share accessed) or 5142/5144 (network share deleted/modified) from the Security log, and no PowerShell script block logging of the actual technique execution — only test framework boilerplate. The Sysmon configuration's include-mode filtering captured the suspicious processes (cmd.exe, net.exe) but may have missed benign processes that could provide additional context about the environment state.

## Assessment

This dataset provides excellent telemetry for detecting the command-line execution patterns of network share removal attempts, even when the operation fails. The combination of Security 4688 events with full command-line logging and Sysmon EID 1 events offers comprehensive process creation coverage for building detections. The clear process chain (PowerShell → cmd → net → net1) with preserved command-line arguments makes this particularly valuable for detection engineering focused on process-based indicators. However, the dataset's utility is somewhat limited by the failed execution — successful share deletion would generate additional event types that could strengthen detections. The error exit codes (0x2) provide a useful indicator that the technique was attempted but unsuccessful, which is still valuable for threat hunting scenarios.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** — Monitor Security 4688 and Sysmon EID 1 for `net share` commands with `/delete` parameter, especially when executed through cmd.exe spawned from scripting engines like PowerShell

2. **Process chain analysis** — Detect the specific parent-child relationship of powershell.exe → cmd.exe → net.exe → net1.exe, particularly when the net commands include share manipulation arguments

3. **Privilege escalation context** — Alert on network share deletion commands executed with SYSTEM privileges, as shown by the NT AUTHORITY\SYSTEM user context in all process creation events

4. **Failed operation detection** — Monitor for net.exe and net1.exe processes exiting with status 0x2 (ERROR_FILE_NOT_FOUND) when executing share deletion commands, which may indicate reconnaissance or cleanup attempts against non-existent shares

5. **PowerShell process access monitoring** — Use Sysmon EID 10 events to detect when PowerShell processes gain full access (0x1FFFFF) to command-line utilities like cmd.exe, which may indicate script-driven system administration or cleanup activities

6. **Cross-process correlation** — Combine the whoami.exe execution (likely reconnaissance) with subsequent network share deletion attempts from the same PowerShell session to identify potential adversary workflows
