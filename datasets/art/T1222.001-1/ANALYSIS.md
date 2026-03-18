# T1222.001-1: Windows File and Directory Permissions Modification — Take ownership using takeown utility

## Technique Context

T1222.001 Windows File and Directory Permissions Modification is a defense evasion technique where adversaries modify file or directory permissions to circumvent access controls and hide malicious activity. The `takeown` utility is a legitimate Windows command-line tool that allows users to take ownership of files and directories, effectively bypassing permission restrictions. Attackers commonly use this technique to gain access to sensitive files, modify system configurations, or establish persistence mechanisms in directories they shouldn't normally access.

The detection community focuses heavily on monitoring permission modification utilities like `takeown`, `icacls`, and `attrib`, as their abuse is a strong indicator of privilege escalation attempts or defense evasion activities. These tools are commonly used in conjunction with other techniques like file system manipulation and persistence establishment.

## What This Dataset Contains

This dataset captures a complete execution of the `takeown` utility targeting a test folder. The process chain shows:

**Process Creation Chain:**
- PowerShell (PID 42620) → cmd.exe (PID 41932) → takeown.exe (PID 23124)

**Key Command Lines:**
- Security Event 4688: `"cmd.exe" /c takeown.exe /f %temp%\T1222.001_takeown_folder /r`
- Security Event 4688: `takeown.exe  /f C:\Windows\TEMP\T1222.001_takeown_folder /r`
- Sysmon Event 1: `takeown.exe  /f C:\Windows\TEMP\T1222.001_takeown_folder /r`

**Process Access Events:**
- Sysmon Event 10: PowerShell accessing cmd.exe with GrantedAccess 0x1FFFFF
- Sysmon Event 10: PowerShell accessing whoami.exe with GrantedAccess 0x1FFFFF

**Exit Status Indicators:**
- Security Event 4689 shows takeown.exe exited with status 0x1 (error/failure)
- Security Event 4689 shows cmd.exe also exited with status 0x1

**Privilege Information:**
- Security Event 4703 shows PowerShell enabled SeTakeOwnershipPrivilege among other system privileges

## What This Dataset Does Not Contain

The dataset lacks several key elements typically associated with successful file ownership modification:

**Missing File System Events:** No Sysmon Event 11 (File Created) events show the actual creation or modification of files within the target directory, suggesting the takeown operation may have failed or the target directory didn't exist.

**No Object Access Events:** Windows audit policy shows "object_access: none", so there are no Security Event 4656/4658/4663 events that would show actual file access attempts or permission changes.

**Limited Process Coverage:** The sysmon-modular config's include-mode filtering captured takeown.exe because it matches known LOLBin patterns, but may miss other permission-related utilities in different attack scenarios.

**Success Telemetry:** The exit code 0x1 from both takeown.exe and cmd.exe indicates the operation failed, so this represents attempt telemetry rather than successful permission modification.

## Assessment

This dataset provides excellent telemetry for detecting attempted file ownership modification using takeown.exe. The combination of Security Event 4688 process creation logs with command-line arguments and Sysmon Event 1 process creation provides comprehensive coverage of the technique execution. The privilege escalation context is particularly valuable, with Event 4703 showing SeTakeOwnershipPrivilege being enabled.

However, the dataset's utility is somewhat limited by the failed execution (exit code 0x1) and missing object access auditing. For comprehensive file permission modification detection, organizations would benefit from enabling object access auditing to capture the actual file system changes, not just the tool execution attempts.

The process access events (Sysmon Event 10) add valuable context about PowerShell's interaction with child processes, which could help identify automation frameworks or scripted attacks.

## Detection Opportunities Present in This Data

1. **Takeown.exe Process Creation** - Monitor Security Event 4688 and Sysmon Event 1 for takeown.exe execution with command-line analysis for suspicious target paths (e.g., system directories, other users' profiles)

2. **Privilege Escalation Context** - Correlate Security Event 4703 SeTakeOwnershipPrivilege usage with subsequent file permission utilities like takeown.exe

3. **PowerShell-to-Takeown Process Chain** - Detect PowerShell spawning cmd.exe which then executes takeown.exe, indicating potential scripted permission modification attempts

4. **Recursive Permission Changes** - Monitor for takeown.exe with `/r` flag indicating recursive operations across directory trees

5. **Process Access Patterns** - Use Sysmon Event 10 to identify PowerShell processes accessing permission modification utilities with high privileges (0x1FFFFF)

6. **Failed Execution Analysis** - Monitor Security Event 4689 exit codes for takeown.exe failures, which may indicate reconnaissance attempts against protected directories

7. **Cross-Process Correlation** - Combine whoami.exe execution (user discovery) with subsequent takeown.exe execution as potential privilege escalation sequence
