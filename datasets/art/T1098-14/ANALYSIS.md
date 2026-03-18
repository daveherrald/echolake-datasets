# T1098-14: Account Manipulation — Domain Password Policy Check: No Lowercase Character in Password

## Technique Context

T1098 (Account Manipulation) encompasses various methods attackers use to maintain access by modifying account properties or creating new accounts. This specific test (T1098-14) simulates an attacker attempting to change a domain user's password to one that violates password policy by containing no lowercase characters ("UPPER-LONG-SPECIAL-333"). This technique is significant because it demonstrates how attackers might try to circumvent password complexity requirements or test password policy enforcement. Detection engineers focus on monitoring PowerShell execution of Active Directory cmdlets, particularly `Set-ADAccountPassword`, and identifying password policy violations or failed authentication attempts that could indicate policy testing.

## What This Dataset Contains

This dataset captures a PowerShell-based password change attempt executed by the NT AUTHORITY\SYSTEM account. The primary evidence appears in Security event 4688, which shows powershell.exe being launched with a command line containing the full password manipulation script. The command attempts to read stored credentials from `$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt`, then execute `Set-ADAccountPassword -Identity $env:USERNAME -OldPassword $cred.password -NewPassword $newPassword` where the new password is "UPPER-LONG-SPECIAL-333".

PowerShell script block logging (EID 4104) captured the same password change script content across two separate script blocks, showing the full logic including credential file validation, password comparison, and error handling. The script includes specific error handling for error code 86 (incorrect stored password) and success messaging.

Sysmon captured extensive process creation and DLL loading activity, including EID 1 events for whoami.exe execution and the main PowerShell process with the password manipulation command line. Process access events (EID 10) show PowerShell accessing the whoami.exe and child PowerShell processes, indicating typical script execution patterns.

## What This Dataset Does Not Contain

The dataset lacks any Active Directory-specific events that would indicate whether the password change attempt actually succeeded or failed against domain policy. There are no Security events like 4723 (password change attempt), 4724 (password reset attempt), or 4625 (failed logon) that would show the outcome of the policy validation.

The PowerShell operational log contains mostly test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than detailed execution results or error messages from the Set-ADAccountPassword cmdlet. Since this test runs as SYSTEM on a domain-joined machine, the actual policy enforcement would occur at the domain controller level, which is not instrumented in this dataset.

No network traffic to domain controllers is captured in Sysmon EID 3 events, which would typically accompany legitimate domain authentication or password change operations.

## Assessment

This dataset provides good visibility into the PowerShell execution vector used to attempt password policy manipulation, with excellent command-line visibility through both Security 4688 and Sysmon EID 1 events. The script block logging gives complete insight into the attacker's methodology and error handling logic.

However, the dataset's value for detecting the core technique is limited by the lack of domain controller logs or client-side authentication failure events. The telemetry effectively captures the attempt but not the policy enforcement outcome, which is critical for understanding whether the manipulation succeeded or triggered security controls.

The rich process execution telemetry makes this dataset valuable for detecting the delivery mechanism (PowerShell execution of AD cmdlets) but less useful for detecting the actual account manipulation success or failure.

## Detection Opportunities Present in This Data

1. **PowerShell Active Directory cmdlet execution** - Monitor for `Set-ADAccountPassword` in command lines or script blocks, particularly when executed with hardcoded passwords
2. **Suspicious password patterns in command lines** - Detect passwords that appear to violate common complexity requirements (all uppercase, obvious patterns like "UPPER-LONG-SPECIAL-333")
3. **Credential file manipulation** - Monitor for PowerShell scripts accessing credential files in `%LOCALAPPDATA%\AtomicRedTeam\` or similar non-standard locations
4. **Process chain analysis** - Detect PowerShell spawning from system processes and subsequently executing domain management cmdlets
5. **Script block content analysis** - Hunt for PowerShell scripts containing password manipulation logic combined with credential file operations
6. **Administrative account behavior** - Flag SYSTEM account executing user password management operations, which is atypical for normal system operations
