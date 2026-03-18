# T1136.001-5: Local Account — Create a new user in PowerShell

## Technique Context

T1136.001 (Create Account: Local Account) is a persistence technique where adversaries create new local user accounts to maintain access to compromised systems. This technique is particularly valuable for attackers because local accounts provide a persistent foothold that survives system reboots and doesn't rely on domain connectivity. The detection community focuses heavily on monitoring user account creation activities through both Windows event logs (Security event 4720) and PowerShell script block logging, as well as process execution patterns involving user management utilities like net.exe, New-LocalUser cmdlets, and lusrmgr.msc.

PowerShell-based account creation using the New-LocalUser cmdlet is especially concerning because it's a native Windows capability that doesn't require additional tools, and PowerShell's ubiquity in enterprise environments can make malicious usage blend with legitimate administrative activities.

## What This Dataset Contains

This dataset captures a successful PowerShell-based local user creation using the `New-LocalUser` cmdlet. The core malicious activity is clearly visible in the Security event 4688 showing process creation of `powershell.exe` with the command line: `"powershell.exe" & {New-LocalUser -Name \"T1136.001_PowerShell\" -NoPassword}`.

PowerShell script block logging (event 4104) captures the actual cmdlet execution: `New-LocalUser -Name "T1136.001_PowerShell" -NoPassword` along with command invocation logging (event 4103) showing the parameter bindings for the New-LocalUser cmdlet. The PowerShell events also contain extensive test framework boilerplate including `Set-StrictMode` and `Set-ExecutionPolicy Bypass` commands.

Sysmon provides rich process creation telemetry showing the process chain: a parent PowerShell process (PID 13072) spawns a child PowerShell process (PID 15036) that executes the user creation command. Sysmon also captures process access events (EID 10) showing PowerShell accessing both whoami.exe and the child PowerShell process with full access rights (0x1FFFFF).

The Security channel shows privilege escalation activity with event 4703 documenting extensive token right adjustments including SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and other high-privilege capabilities being enabled for the PowerShell process.

## What This Dataset Does Not Contain

Critically, this dataset lacks the definitive evidence of successful user account creation. There are no Security event 4720 (A user account was created) logs, which are the primary indicators that the New-LocalUser operation actually succeeded. This absence could indicate several scenarios: the account creation failed, Windows audit policy doesn't have account management auditing enabled, or the user creation succeeded but those events weren't captured in this collection window.

The dataset also doesn't contain any SAM database modification events or registry changes that would typically accompany user account creation. Additionally, there are no subsequent logon events (4624/4625) that would demonstrate the newly created account being used.

## Assessment

This dataset provides excellent visibility into PowerShell-based user creation attempts through comprehensive process execution and script block logging, but falls short of confirming whether the technique actually succeeded. The PowerShell telemetry is exemplary for detection engineering — the command line arguments, script blocks, and cmdlet invocations are all clearly captured. However, the absence of Security event 4720 significantly limits the dataset's utility for understanding the complete attack lifecycle.

For detection engineering focused on identifying user creation attempts regardless of success, this data is valuable. For validating successful account creation or testing detections that rely on account management events, additional telemetry would be needed.

## Detection Opportunities Present in This Data

1. PowerShell command line analysis: Detect `New-LocalUser` cmdlet usage through Security event 4688 command line fields or Sysmon event 1 CommandLine fields

2. PowerShell script block monitoring: Alert on script blocks containing `New-LocalUser` cmdlet execution captured in PowerShell event 4104

3. PowerShell cmdlet invocation tracking: Monitor event 4103 for New-LocalUser command invocations with parameter analysis (looking for suspicious usernames or NoPassword parameters)

4. Token privilege escalation detection: Identify Security event 4703 showing multiple high-value privileges being enabled simultaneously (SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, etc.)

5. Process ancestry analysis: Detect PowerShell spawning child PowerShell processes for user management operations through Sysmon event 1 parent-child relationships

6. PowerShell execution policy bypass detection: Monitor for `Set-ExecutionPolicy Bypass` commands in script blocks that precede user management activities

7. Cross-process access patterns: Alert on Sysmon event 10 showing PowerShell processes accessing other processes with full rights (0x1FFFFF) during user creation timeframes
