# T1098-9: Account Manipulation — Password Change on Directory Service Restore Mode (DSRM) Account

## Technique Context

T1098.009 involves modifying the Directory Service Restore Mode (DSRM) account password on domain controllers to establish persistent access. DSRM is a safe mode boot option for Windows domain controllers that allows administrators to perform maintenance when Active Directory is offline. The DSRM account is a local administrator account that exists on every domain controller and can be used for emergency access.

Attackers target this technique because the DSRM account provides privileged access that can persist even if domain accounts are remediated. By synchronizing the DSRM password with a known domain account password using `ntdsutil`, attackers ensure they can maintain access to the domain controller through this local account. The detection community focuses on monitoring `ntdsutil` usage, particularly the "set dsrm password" and "sync from domain account" commands, as legitimate use of these functions is rare and typically occurs during planned maintenance windows.

## What This Dataset Contains

This dataset captures a failed attempt to modify the DSRM password using `ntdsutil`. The key evidence shows:

Security event 4688 documents the command execution: `"cmd.exe" /c ntdsutil "set dsrm password" "sync from domain account %username%" "q" "q"` spawned from PowerShell process 37008. The subsequent Security event 4689 shows the cmd.exe process exiting with status code 0x1, indicating failure.

Sysmon provides additional process creation telemetry via event ID 1, showing the same `ntdsutil` command line with cmd.exe (PID 35720) as a child of powershell.exe. The Sysmon events also capture a `whoami.exe` execution (PID 23768) that appears to be reconnaissance, with process access events (EID 10) showing PowerShell accessing both the whoami and cmd processes.

The PowerShell operational log contains only test framework boilerplate (Set-ExecutionPolicy Bypass commands and error handling scriptblocks), with no evidence of the actual technique implementation script.

## What This Dataset Does Not Contain

This dataset lacks evidence of successful DSRM password modification. The cmd.exe exit status 0x1 indicates the `ntdsutil` command failed, likely because this workstation (ACME-WS02) is not a domain controller. The technique requires execution on an actual domain controller where the DSRM account exists.

Missing are any Security events related to account management (event IDs 4720-4738 series), which would appear if the DSRM account password was successfully modified. There are no ntdsutil.exe process creation events in Sysmon, suggesting the command failed before launching the actual utility. Registry modifications to HKLM\System\CurrentControlSet\Control\Lsa that enable DSRM network logon are also absent.

## Assessment

This dataset provides limited value for detection engineering specific to T1098.009 because it captures only a failed attempt on an inappropriate target system. However, it does demonstrate the command-line patterns that would appear during an actual attack attempt. The Security 4688 events with command-line logging and Sysmon process creation events effectively capture the suspicious `ntdsutil` usage patterns that are key indicators of this technique.

For building robust detections, this data would be more valuable if it came from a domain controller where the technique could complete successfully, generating the full sequence of events including actual DSRM account modifications and potential registry changes.

## Detection Opportunities Present in This Data

1. **Suspicious ntdsutil Command Lines**: Security 4688 and Sysmon EID 1 both capture the command `ntdsutil "set dsrm password" "sync from domain account %username%"` which is a strong indicator of T1098.009 attempt

2. **PowerShell Spawning Administrative Tools**: Process creation telemetry shows powershell.exe spawning cmd.exe with ntdsutil commands, indicating potential scripted attack automation

3. **SYSTEM Context Execution**: The ntdsutil command executed under NT AUTHORITY\SYSTEM context, which while expected for legitimate DSRM operations, combined with the suspicious command pattern warrants investigation

4. **Process Access Patterns**: Sysmon EID 10 shows PowerShell accessing spawned child processes (whoami, cmd) with full access rights (0x1FFFFF), indicating potential process manipulation or monitoring

5. **Failed Command Execution**: The cmd.exe exit status 0x1 in Security 4689 events can help identify failed attack attempts that may indicate reconnaissance or testing phases of an attack
