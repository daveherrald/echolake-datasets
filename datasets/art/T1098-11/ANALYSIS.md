# T1098-11: Account Manipulation — Domain Password Policy Check: No Number in Password

## Technique Context

T1098 Account Manipulation encompasses various methods attackers use to modify user accounts to maintain persistence or escalate privileges. This specific test (T1098-11) focuses on domain password policy manipulation, particularly attempting to set a password that violates common organizational password complexity requirements by containing no numbers. In real attacks, adversaries might modify password policies to weaken security controls, create accounts with weak passwords, or manipulate existing accounts to maintain access. The detection community typically focuses on monitoring Active Directory changes, PowerShell usage for domain administration, and credential manipulation activities.

## What This Dataset Contains

The dataset captures a failed password change attempt using PowerShell Active Directory cmdlets. Key evidence includes:

**PowerShell Script Block Logging (EID 4104):** The core attack script attempts to change a domain user password to "UpperLowerLong-special" using `Set-ADAccountPassword`. The script includes logic to read existing credentials from `$env:LOCALAPPDATA\AtomicRedTeam\$env:USERNAME.txt` and error handling for credential validation.

**Process Creation (Security EID 4688, Sysmon EID 1):** Multiple PowerShell processes spawn, including one with the full command line showing the password change script. The child process `whoami.exe` executes to identify the current user context.

**Process Access (Sysmon EID 10):** PowerShell processes access each other with full access rights (0x1FFFFF), indicating process injection or debugging capabilities commonly seen with PowerShell execution.

**Privilege Adjustment (Security EID 4703):** The PowerShell process enables extensive system privileges including SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, and SeRestorePrivilege, typical for domain administrative operations.

**File Operations (Sysmon EID 11):** PowerShell creates startup profile data files, indicating script initialization and execution preparation.

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence of actual domain password policy manipulation. Notably missing are:

- No Security Event ID 4739 (Domain Policy Changed) events that would indicate successful password policy modifications
- No Security Event ID 4724 (Password Reset) or 4723 (Password Change) events showing actual password changes
- No Active Directory operational logs or domain controller events
- No network authentication events (4768/4769) that would show password validation attempts
- The technique appears to have failed before making actual domain changes, likely due to missing prerequisites (credential file not found or invalid credentials)

## Assessment

This dataset provides excellent telemetry for detecting the attempt to manipulate domain passwords via PowerShell but lacks evidence of successful execution. The PowerShell script block logging is particularly valuable, capturing the complete attack script including the target password and error handling logic. The process creation events with full command lines provide clear indicators of suspicious domain administration activity. However, the absence of actual domain events limits this dataset's utility for understanding successful password policy manipulation. The telemetry quality is strong for initial detection but incomplete for full attack lifecycle analysis.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis:** Monitor EID 4104 for `Set-ADAccountPassword` cmdlet usage, especially with hardcoded passwords in command lines
2. **Suspicious Command Line Patterns:** Detect Security EID 4688 events containing PowerShell execution with credential manipulation functions and password strings
3. **Process Chain Analysis:** Identify PowerShell spawning child processes like `whoami.exe` as potential reconnaissance before credential manipulation
4. **Privilege Escalation Detection:** Alert on EID 4703 events showing PowerShell processes acquiring multiple sensitive privileges simultaneously
5. **File System Monitoring:** Track EID 11 creation of credential storage files in user-writable locations like `%LOCALAPPDATA%\AtomicRedTeam\`
6. **PowerShell Module Loading:** Monitor Sysmon EID 7 for loading of System.Management.Automation.dll in conjunction with credential-related activities
7. **Process Access Patterns:** Detect Sysmon EID 10 showing PowerShell processes accessing other PowerShell instances with full access rights as potential injection attempts
