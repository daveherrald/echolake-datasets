# T1098-10: Account Manipulation — Domain Password Policy Check: Short Password

## Technique Context

T1098 Account Manipulation involves adversaries modifying account properties to maintain persistence or escalate privileges. This specific test (T1098-10) simulates an attempt to change a domain user's password to a weak password ("Uplow-1") that would typically violate domain password policy requirements. In real attack scenarios, adversaries might attempt password changes to maintain access, bypass security controls, or test password policy enforcement. Detection engineers focus on monitoring password change events, PowerShell execution with credential manipulation cmdlets, and attempts to bypass domain security policies.

## What This Dataset Contains

This dataset captures a PowerShell-based password change attempt executed as NT AUTHORITY\SYSTEM. The core activity shows in Security event 4688 with the full command line: `"powershell.exe" & {$credFile = \"$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt\"... Set-ADAccountPassword -Identity $env:USERNAME -OldPassword $cred.password -NewPassword $newPassword...}`. 

PowerShell events 4104 show the actual script block containing the `Set-ADAccountPassword` cmdlet execution and credential file operations at `$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt`. The script attempts to read stored credentials, validate the new password isn't identical to the stored one, and execute the password change.

Sysmon captures the process creation (EID 1) for both whoami.exe (system owner discovery) and the PowerShell process containing the password change script. Multiple PowerShell processes show .NET runtime loading (EIDs 7) and named pipe creation (EIDs 17) indicating PowerShell remoting capabilities.

## What This Dataset Does Not Contain

The dataset lacks any domain controller interaction events, meaning either the password change was blocked before reaching the DC, failed due to missing prerequisites (no credential file), or was filtered by the collection scope. No Security events related to password changes (4723, 4724) or account management appear, suggesting the operation didn't successfully complete. 

Missing are any LDAP or Kerberos authentication events that would indicate actual communication with domain services. The exit status codes in Security 4689 events show mixed results (0x0 and 0x1), but without explicit error reporting, the actual failure reason isn't captured.

## Assessment

This dataset provides moderate value for detection engineering focused on credential manipulation attempts rather than successful password changes. The Security channel's command-line logging captures the full PowerShell script including the `Set-ADAccountPassword` cmdlet usage, which is the primary detection artifact. PowerShell script block logging (4104) complements this with the actual script content.

The dataset is strongest for detecting the attempt phase of password manipulation but lacks telemetry showing whether domain policy enforcement blocked the operation. For building detections around password policy violations or successful account manipulation, additional domain controller logs would be needed.

## Detection Opportunities Present in This Data

1. **PowerShell Set-ADAccountPassword Usage** - Monitor PowerShell events 4104 and Security 4688 for `Set-ADAccountPassword` cmdlet execution, especially when combined with credential file operations and hardcoded passwords.

2. **Credential File Operations** - Detect PowerShell scripts accessing files in AtomicRedTeam directories or similar testing frameworks, particularly those involving credential storage and retrieval patterns.

3. **Weak Password Patterns in Command Lines** - Security 4688 command-line logging captures hardcoded password strings like "Uplow-1" that could indicate password policy testing or weak credential usage.

4. **System Account PowerShell Execution** - Monitor for PowerShell processes running as NT AUTHORITY\SYSTEM performing account manipulation operations, which is unusual in normal operations.

5. **Process Chain Analysis** - Correlate parent PowerShell processes spawning additional PowerShell instances with credential manipulation scripts, indicating potential automation or persistence mechanisms.

6. **Named Pipe Creation Patterns** - Sysmon EID 17 shows PowerShell named pipes that could indicate remoting or inter-process communication for credential operations.
