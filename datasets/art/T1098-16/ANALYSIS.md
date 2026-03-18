# T1098-16: Account Manipulation — Domain Password Policy Check: Common Password Use

## Technique Context

T1098 Account Manipulation encompasses adversary activities that modify account settings, permissions, or properties to maintain persistence or escalate privileges. This specific test (T1098-16) focuses on domain password policy enforcement by attempting to change a user's password to a predictable, seasonal pattern ("Spring2026!"). This technique matters because weak password policies and predictable password patterns are common attack vectors for maintaining persistence and credential stuffing attacks. Detection engineers typically focus on identifying password changes, especially those that follow predictable patterns, unusual privilege escalations during password operations, and PowerShell usage for Active Directory account manipulation.

## What This Dataset Contains

The dataset captures a PowerShell-based password change attempt that appears to have failed due to missing prerequisites. The primary evidence is in Security event 4688, which shows the full command line of a PowerShell process attempting to execute a password change script:

- **Process creation**: Security 4688 shows `powershell.exe` with an extensive command line containing `Set-ADAccountPassword -Identity $env:USERNAME -OldPassword $cred.password -NewPassword $newPassword`
- **Credential file operations**: The script attempts to read credentials from `$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt`
- **Password pattern**: The new password follows the pattern `Spring$((Get-Date).Year)!` (Spring2026!)
- **Error handling**: The script includes logic to handle error code 86 and credential file cleanup
- **PowerShell telemetry**: Event 4104 script block logging captures the actual script execution, showing two script blocks with the full password change logic
- **Supporting processes**: Sysmon EID 1 captures `whoami.exe` execution (T1033 System Owner/User Discovery) before the password change attempt
- **Process relationships**: Clear parent-child relationship between the initial PowerShell process and the spawned password change PowerShell process

## What This Dataset Does Not Contain

The dataset is missing several key elements due to the test's failure to meet prerequisites:

- **Actual Active Directory operations**: No domain controller communication or LDAP queries are visible
- **Success telemetry**: The script exits early due to missing credential files, so no successful password change occurs
- **Domain-specific logs**: No Security events related to account management (4723, 4724, 4738) that would normally accompany successful password changes
- **Network activity**: Sysmon network connection events that would show communication with domain controllers
- **Group Policy interactions**: No evidence of password policy evaluation or enforcement
- **Kerberos ticket activity**: Missing authentication-related Security events that would accompany domain password operations

## Assessment

This dataset provides moderate value for detection engineering focused on the attempt phase of password manipulation attacks. The Security 4688 command-line logging captures the complete attack methodology, including the predictable password pattern and credential management approach. The PowerShell script block logging (EID 4104) provides excellent visibility into the actual code being executed. However, the dataset's utility is limited by the technique's failure to execute fully—it demonstrates detection opportunities for reconnaissance and preparation phases but lacks the domain-level telemetry that would accompany successful account manipulation. For building detections of attempted password policy circumvention and seasonal password patterns, this data is quite useful. For understanding the full attack lifecycle including domain controller interactions, additional successful execution data would be needed.

## Detection Opportunities Present in This Data

1. **Predictable password patterns in command lines** - Security 4688 process creation events containing `Spring$((Get-Date).Year)!` or similar seasonal password patterns in PowerShell command lines

2. **Active Directory PowerShell module usage for password changes** - Process creation events with command lines containing `Set-ADAccountPassword` combined with credential file operations

3. **Atomic Red Team artifact detection** - File operations or command line references to `\AtomicRedTeam\` directories, particularly credential storage patterns

4. **PowerShell script block analysis for account manipulation** - Event 4104 script blocks containing `Set-ADAccountPassword`, `ConvertTo-SecureString`, and credential file operations in sequence

5. **Credential file enumeration patterns** - PowerShell processes checking for existence of credential files in `LOCALAPPDATA` with specific naming conventions

6. **Process chain analysis** - Parent PowerShell processes spawning child PowerShell processes with lengthy command lines containing Active Directory cmdlets

7. **whoami.exe execution before password operations** - Sysmon EID 1 showing `whoami.exe` execution immediately followed by PowerShell processes attempting account manipulation
