# T1098-2: Account Manipulation — Domain Account and Group Manipulate

## Technique Context

T1098.002 (Domain Account and Group Manipulate) is a persistence and privilege escalation technique where adversaries modify domain accounts and group memberships to maintain access or elevate privileges. Attackers commonly use this technique to add compromised or newly created accounts to privileged groups like Domain Admins, Enterprise Admins, or administrative groups. The technique is particularly valuable because it provides legitimate access paths that blend with normal administrative activity. Detection engineers typically focus on monitoring group membership changes, especially additions to high-privilege groups, account creation followed by immediate privilege escalation, and the use of PowerShell cmdlets like `New-ADUser` and `Add-ADGroupMember`.

## What This Dataset Contains

This dataset captures a failed attempt at domain account manipulation using PowerShell's Active Directory module. The Security event log shows the complete process chain with Security 4688 events revealing the PowerShell command line: `"powershell.exe" & {$x = Get-Random -Minimum 2 -Maximum 99; $y = Get-Random -Minimum 2 -Maximum 99; $z = Get-Random -Minimum 2 -Maximum 99; $w = Get-Random -Minimum 2 -Maximum 99; Import-Module ActiveDirectory; $account = "atr--$x$y$z"; New-ADUser -Name $account -GivenName "Test" -DisplayName $account -SamAccountName $account -Surname $account -Enabled:$False; Add-ADGroupMember "Domain Admins" $account}`. The PowerShell event log contains detailed script block logging (4104 events) showing the complete attack script and a critical 4103 event documenting the failure: `NonTerminatingError(Import-Module): "The specified module 'ActiveDirectory' was not loaded because no valid module file was found in any module directory."` Sysmon captures the process creation (EID 1) for both the parent PowerShell process and a child `whoami.exe` execution for reconnaissance, along with extensive .NET framework DLL loading events (EID 7) as PowerShell initializes.

## What This Dataset Does Not Contain

The dataset lacks the actual domain manipulation events because the Active Directory PowerShell module was not available on this workstation. There are no account creation events, group membership modification events, or domain controller communication logs. The Windows Security log contains no account management events (4720 for user creation, 4728 for group membership changes) that would normally accompany successful execution of this technique. Additionally, there are no network events showing LDAP/Kerberos traffic to domain controllers, and no audit policy events related to directory service access since the technique failed at the module import stage.

## Assessment

This dataset provides excellent visibility into the attempt telemetry for T1098.002, particularly the PowerShell command-line evidence and script block logging that reveals the attacker's intent. The Security 4688 events with full command-line logging and PowerShell 4104 script block events offer comprehensive coverage of the attack vector. However, the failure to load the Active Directory module significantly limits the dataset's value for understanding the complete attack lifecycle and domain-level detection opportunities. For building detections around PowerShell-based domain manipulation attempts, this data is valuable, but additional datasets with successful execution would be needed to develop comprehensive coverage.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor PowerShell 4104 events for suspicious Active Directory cmdlets like `New-ADUser` and `Add-ADGroupMember`, especially when used together in a single script block to create accounts and immediately add them to privileged groups.

2. **Command Line Pattern Detection** - Detect Security 4688 events containing PowerShell command lines with both user creation and group membership modification operations, particularly targeting sensitive groups like "Domain Admins".

3. **PowerShell Module Loading Failures** - Alert on PowerShell 4103 events with `NonTerminatingError` messages related to Active Directory module loading, as this may indicate reconnaissance or failed privilege escalation attempts.

4. **Suspicious Process Chains** - Monitor for PowerShell processes spawning reconnaissance tools like `whoami.exe` in conjunction with Active Directory-related commands, as captured in the Sysmon process creation events.

5. **Random Account Name Generation** - Detect PowerShell scripts using `Get-Random` cmdlets to generate account names, especially with patterns like "atr--" prefix followed by random numbers, which may indicate automated account creation tools.

6. **Privilege Escalation Intent** - Flag PowerShell executions that attempt to import Active Directory modules followed by operations targeting high-privilege groups, even when the operations fail due to missing modules or permissions.
