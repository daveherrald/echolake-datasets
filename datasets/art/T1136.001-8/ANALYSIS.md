# T1136.001-8: Local Account — Create a new Windows admin user

## Technique Context

T1136.001 (Create Account: Local Account) represents a fundamental persistence technique where attackers create new local user accounts to maintain access to compromised systems. This technique is particularly valuable because it establishes legitimate-appearing credentials that can persist across reboots and may evade detection if proper account monitoring isn't in place. Attackers often combine user creation with privilege escalation by adding the new account to administrative groups, providing them with elevated access for future operations.

The detection community focuses heavily on monitoring `net user` and `net localgroup` commands, PowerShell user management cmdlets, and Windows Security events that record account creation and modification activities. Modern detection strategies also look for unusual account naming patterns, rapid user creation followed by privilege escalation, and accounts created outside normal business processes.

## What This Dataset Contains

This dataset captures a complete T1136.001 execution using the classic `net user` approach. The attack chain begins with PowerShell executing: `"cmd.exe" /c net user /add "T1136.001_Admin" "T1136_pass" & net localgroup administrators "T1136.001_Admin" /add`

**Process Creation Chain (Security 4688 events):**
- PowerShell spawns `cmd.exe` with the full command line containing both user creation and group addition
- `cmd.exe` launches `net.exe` with arguments `user /add "T1136.001_Admin" "T1136_pass"`
- `net.exe` spawns `net1.exe` (the actual implementation) with the same user creation arguments
- `cmd.exe` then launches a second `net.exe` with arguments `localgroup administrators "T1136.001_Admin" /add`
- The second `net.exe` spawns `net1.exe` for group membership modification

**Sysmon Process Creation (EID 1) events:**
- Captures the same process chain with additional detail including file hashes, parent-child relationships, and integrity levels
- All processes run with System integrity level under NT AUTHORITY\SYSTEM context
- Sysmon RuleName tags identify these as `technique_id=T1018,technique_name=Remote System Discovery` (likely due to net.exe usage patterns)

**Process Access Events (Sysmon EID 10):**
- PowerShell performs process access (0x1FFFFF permissions) on both spawned child processes
- Call traces show .NET assembly involvement in the process management

## What This Dataset Does Not Contain

This dataset lacks several critical detection artifacts typically associated with account creation:

**Missing Security Events:** No Security event ID 4720 (A user account was created) or 4732 (A member was added to a security-enabled local group) events appear in the data. These are the primary Windows audit events for detecting this technique, suggesting either incomplete audit policy coverage or the events were generated but not captured in this specific timeframe.

**Missing Account Management Evidence:** The dataset shows the process execution but not the actual account management operations' success or failure status codes.

**Limited PowerShell Logging:** The PowerShell events (EID 4104/4103) contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual user creation commands, indicating the attack used direct process execution rather than PowerShell cmdlets.

## Assessment

This dataset provides excellent process-level telemetry for detecting T1136.001 through command-line analysis and process chain monitoring. The Security 4688 events with command-line logging offer clear, high-fidelity detection opportunities through the explicit `net user /add` and `net localgroup administrators /add` command patterns. However, the absence of Security 4720/4732 events significantly limits the dataset's value for account management audit trail analysis.

The Sysmon coverage is comprehensive for process tracking but the technique classification appears incorrect (labeling net.exe usage as Remote System Discovery rather than Account Creation). For production detection engineering, this dataset would be most valuable for developing process-based detection rules rather than account audit monitoring.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security 4688 events containing `net user /add` followed by username and password parameters in the Process Command Line field

2. **Administrative privilege escalation sequence** - Security 4688 events showing `net localgroup administrators` with `/add` parameter targeting the newly created username

3. **Process chain analysis** - Sysmon EID 1 events showing cmd.exe spawning net.exe which spawns net1.exe in rapid succession with account creation arguments

4. **Compound command detection** - Security 4688 cmd.exe creation with command line containing both user creation and group modification operations joined by `&`

5. **Parent process context** - Process creation events showing PowerShell as the parent of cmd.exe executing account creation commands

6. **Process access correlation** - Sysmon EID 10 events showing PowerShell performing full access (0x1FFFFF) to net.exe child processes, indicating programmatic control

7. **Timing-based detection** - Rapid sequence of account creation followed immediately by administrative group addition within seconds
