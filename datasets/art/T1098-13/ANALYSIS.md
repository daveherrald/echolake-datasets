# T1098-13: Account Manipulation — Domain Password Policy Check: No Uppercase Character in Password

## Technique Context

T1098 Account Manipulation encompasses adversary attempts to modify user account properties to maintain access or escalate privileges. This specific test (T1098-13) focuses on domain password policy manipulation by attempting to change a domain account's password to one that violates common password complexity requirements — specifically, a password containing no uppercase characters ("lower-long-special-333"). Attackers use this technique to weaken password policies, establish persistence with known credentials, or test domain password policy enforcement. The detection community focuses on monitoring password change operations, policy modification events, and authentication attempts with weak credentials that may indicate policy bypasses or credential stuffing attacks.

## What This Dataset Contains

This dataset captures an Active Directory password change attempt using PowerShell's `Set-ADAccountPassword` cmdlet. The primary evidence is found in Security event 4688, which shows a PowerShell process executing with the command line containing the full password change script: `"powershell.exe" & {$credFile = "$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt"...Set-ADAccountPassword -Identity $env:USERNAME -OldPassword $cred.password -NewPassword $newPassword...}`. The script contains hardcoded credentials and attempts to change the password to "lower-long-special-333", clearly visible in the command line. Supporting telemetry includes Sysmon process creation events (EID 1) for powershell.exe and whoami.exe processes, PowerShell script block logging (EID 4104) capturing the actual script execution, and multiple DLL loading events showing .NET framework initialization and Windows Defender integration. The test runs as NT AUTHORITY\SYSTEM, creating child PowerShell processes that handle the credential operations.

## What This Dataset Does Not Contain

The dataset does not contain any Active Directory-specific logs that would show whether the password change operation succeeded or failed — there are no domain controller logs, account management events (Security 4724/4738), or LDAP operation logs. The PowerShell process exits with status 0x0, but this only indicates the process terminated normally, not whether the password change was successful. Additionally, there are no authentication events (4624/4625) showing subsequent logon attempts with the new password, no Group Policy events that might indicate password policy enforcement, and no directory service logs that would reveal the actual outcome of the `Set-ADAccountPassword` operation. The absence of error handling in the visible script blocks suggests either the operation completed without PowerShell-level errors or error output was not captured in this telemetry.

## Assessment

This dataset provides excellent visibility into the attack attempt itself through comprehensive process and PowerShell logging, but limited insight into the actual impact on the domain environment. The command-line logging in Security 4688 events is particularly valuable, as it captures the complete attack script including hardcoded credentials and the target weak password. The PowerShell script block logging provides additional forensic context, though much of it consists of test framework boilerplate. For detection engineering focused on identifying password manipulation attempts, this data is highly valuable. However, for understanding the full attack lifecycle or building detections around successful domain policy violations, additional domain controller and Active Directory logs would be essential.

## Detection Opportunities Present in This Data

1. Monitor Security 4688 events for PowerShell command lines containing "Set-ADAccountPassword" cmdlet usage, especially with hardcoded passwords in plaintext
2. Detect PowerShell script block logging (4104) containing Active Directory password manipulation cmdlets combined with credential file operations
3. Alert on PowerShell processes accessing credential files in AtomicRedTeam directories or similar testing framework paths
4. Identify command lines containing password patterns that violate organizational complexity requirements (all lowercase, common patterns)
5. Monitor for PowerShell execution of credential management operations (ConvertTo-SecureString, ConvertFrom-SecureString) in combination with AD cmdlets
6. Detect Sysmon process creation events where PowerShell spawns with command lines exceeding normal length thresholds, potentially indicating embedded scripts
7. Alert on credential file operations in user profile directories combined with subsequent PowerShell AD module usage
8. Monitor for PowerShell processes that create child processes while handling credential operations, indicating potential credential manipulation workflows
