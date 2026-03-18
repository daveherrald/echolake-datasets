# T1098-12: Account Manipulation — Domain Password Policy Check: No Special Character in Password

## Technique Context

T1098 Account Manipulation is a persistence and privilege escalation technique where adversaries modify accounts to maintain access to credentials and systems. This specific test (T1098-12) focuses on password policy validation, attempting to change a user's password to one that lacks special characters ("UpperLowerLong333noSpecialChar"). While not directly malicious, this technique simulates adversary attempts to weaken password complexity requirements or test password policy enforcement. In real attacks, adversaries might use password changes to maintain persistence after initial compromise or to create backdoor accounts with known weak passwords.

The detection community typically focuses on monitoring privileged account modifications, password changes outside normal administrative processes, and attempts to weaken security policies. This test specifically validates whether domain password policies properly enforce special character requirements.

## What This Dataset Contains

The dataset captures a PowerShell-based password change attempt that ultimately fails due to missing prerequisites. The key telemetry includes:

**PowerShell Script Block Logging (EID 4104)** shows the complete password change script: `$newPassword = ConvertTo-SecureString UpperLowerLong333noSpecialChar -AsPlainText -Force` and `Set-ADAccountPassword -Identity $env:USERNAME -OldPassword $cred.password -NewPassword $newPassword`. The script attempts to read stored credentials from `$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt` and change the password to the target weak password.

**Security Event Logs** capture process creation events showing PowerShell execution with the full command line containing the password change script (EID 4688), along with a Security Token Rights Adjusted event (EID 4703) showing elevated privileges being enabled for the PowerShell process.

**Sysmon Events** provide detailed process telemetry including PowerShell process creation (EID 1), image loads for .NET Framework components (EID 7), named pipe creation for PowerShell execution (EID 17), and process access events (EID 10) showing interaction between PowerShell processes.

The test executes as NT AUTHORITY\SYSTEM and spawns multiple PowerShell processes attempting the password change operation, with process IDs 29756, 40044, and 40544 all showing related activity.

## What This Dataset Does Not Contain

This dataset lacks evidence of successful password policy violation because the test fails at the prerequisite stage - no stored credential file exists at `$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt`. The PowerShell script outputs "You must store the password of the current user by running the prerequisite commands first" and exits without attempting the actual `Set-ADAccountPassword` operation.

There are no Active Directory-related events showing actual password change attempts, no domain controller communication logs, and no password policy violation alerts. The test never reaches the point where domain password complexity rules would be evaluated.

The dataset also lacks network traffic to domain controllers, LDAP queries, or authentication events that would occur during a real password change operation.

## Assessment

This dataset has limited utility for detecting actual account manipulation attempts since the technique fails before execution. However, it provides excellent telemetry for detecting the preparation and setup phases of password manipulation attacks. The PowerShell script block logging captures the complete attack methodology, including credential file manipulation and the target weak password in plaintext.

The comprehensive process telemetry from Sysmon and Security logs makes this dataset valuable for understanding the execution patterns of PowerShell-based credential manipulation tools, even when they fail. Detection engineers can use this data to build rules around suspicious PowerShell credential management activities and password manipulation scripts.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - EID 4104 events contain `Set-ADAccountPassword` cmdlets and `ConvertTo-SecureString` operations with plaintext passwords, indicating credential manipulation attempts

2. **Weak Password Detection** - PowerShell script blocks reveal the target password "UpperLowerLong333noSpecialChar" in plaintext, allowing detection of specific weak password patterns

3. **Credential File Access Patterns** - Monitor for PowerShell accessing `$env:LOCALAPPDATA\AtomicRedTeam\*.txt` files or similar credential storage locations

4. **Suspicious PowerShell Execution Context** - Multiple PowerShell processes (PIDs 29756, 40044, 40544) executing under SYSTEM context with credential manipulation scripts

5. **Process Chain Analysis** - Parent-child relationships between PowerShell processes indicate automated or scripted execution rather than interactive use

6. **Named Pipe Creation** - Sysmon EID 17 shows PowerShell communication pipes that could indicate inter-process credential passing

7. **Security Token Privilege Escalation** - EID 4703 shows extensive privilege enabling (SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, etc.) associated with password manipulation attempts
