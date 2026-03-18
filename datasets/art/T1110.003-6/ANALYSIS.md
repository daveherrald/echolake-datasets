# T1110.003-6: Password Spraying — Password Spray Invoke-DomainPasswordSpray Light

## Technique Context

Password spraying (T1110.003) is a credential access technique where attackers attempt authentication with commonly used passwords against many accounts to avoid account lockouts. Unlike traditional brute force attacks that test many passwords against one account, password spraying tests one password against many accounts, typically staying under lockout thresholds. This technique is particularly effective against organizations with weak password policies or common default passwords.

The detection community focuses on identifying authentication patterns characteristic of password spraying: rapid authentication attempts across multiple accounts from single sources, failed logon spikes, and the use of LDAP queries to enumerate domain accounts. This specific test implements a lightweight PowerShell function (`Invoke-dpsLight`) that attempts LDAP authentication against a user list with a single password ("Spring2020").

## What This Dataset Contains

This dataset captures a PowerShell-based password spraying attempt that ultimately fails due to a missing user list file. The Security channel shows the complete process chain with Security EID 4688 capturing the parent PowerShell process and child PowerShell execution with the full `Invoke-dpsLight` command line embedded in the process creation event. The child PowerShell process (PID 23588) was launched with the complete password spraying script as an inline command.

The PowerShell channel contains extensive ScriptBlock logging (EID 4104) showing the `Invoke-dpsLight` function definition with clear LDAP authentication logic: `$Domain_check = New-Object System.DirectoryServices.DirectoryEntry($Domain, $User, $Password)`. The function attempts to authenticate each user from a file (`$env:Temp\usersdpsLight.txt`) against the domain using the hardcoded password "Spring2020".

However, the execution fails immediately with a PowerShell EID 4103 CommandInvocation error: `Get-Content: "Cannot find path 'C:\Windows\TEMP\usersdpsLight.txt' because it does not exist."` The script completes with only a "Finished" message being displayed.

Sysmon captures the process creation chain (EID 1) showing PowerShell spawning whoami.exe for system discovery, then launching the child PowerShell process with the password spraying command line. Process access events (EID 10) show cross-process access between PowerShell instances. No network connections or successful authentications occur due to the missing user list.

## What This Dataset Does Not Contain

This dataset lacks the crucial user enumeration file that would enable actual password spraying attempts. Without `usersdpsLight.txt`, no LDAP authentication attempts occur, meaning there are no Security EID 4624/4625 logon events, no domain controller authentication logs, or network traffic to domain controllers.

The dataset contains no evidence of successful credential validation, account enumeration via LDAP queries, or the typical volume of authentication events that would characterize active password spraying. The technique execution is essentially a dry run that demonstrates the attack methodology without performing actual authentication attempts.

Missing are the Security events that would typically accompany password spraying: multiple 4625 (failed logon) events across different accounts, potential 4740 (account lockout) events if thresholds were exceeded, and corresponding domain controller logs showing the authentication pattern.

## Assessment

This dataset provides limited value for password spraying detection development due to the execution failure. While it captures the attack preparation phase with complete visibility into the PowerShell script deployment and command-line arguments, it lacks the authentication activity that defines password spraying attacks.

The telemetry quality is excellent for understanding PowerShell-based attack delivery mechanisms, with comprehensive process creation logging, script block capture, and cross-process visibility. However, for password spraying specifically, the dataset demonstrates attack setup rather than execution, making it more valuable for understanding attacker methodology than for developing authentication-based detections.

The combination of Security 4688 command-line logging and PowerShell ScriptBlock logging provides complete reconstruction of the attack attempt, which could be valuable for detecting similar attack frameworks even when they fail to execute fully.

## Detection Opportunities Present in This Data

1. **PowerShell ScriptBlock Detection** - EID 4104 events capture the complete `Invoke-dpsLight` function with LDAP authentication patterns, `System.DirectoryServices.DirectoryEntry` instantiation, and hardcoded password usage that could trigger on similar password spraying frameworks.

2. **Suspicious Command Line Patterns** - Security EID 4688 captures the full password spraying script in the process command line, including LDAP connection strings, password variables, and user enumeration logic that could be detected via command-line analysis.

3. **PowerShell Process Relationships** - Sysmon EID 1 events show PowerShell spawning child PowerShell processes with inline scripts, a pattern often associated with attack framework execution and payload delivery.

4. **LDAP Authentication Preparation** - PowerShell EID 4103 CommandInvocation events show Get-Content attempts against user list files and ADSI/DirectoryEntry object creation, indicating preparation for domain authentication attacks.

5. **File Access Pattern Detection** - The failed attempt to access `usersdpsLight.txt` in `$env:Temp` represents a common pattern where attackers stage user enumeration files for bulk authentication attacks.
