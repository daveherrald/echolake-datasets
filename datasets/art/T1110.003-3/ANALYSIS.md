# T1110.003-3: Password Spraying — Password spray all Active Directory domain users with a single password via LDAP against domain controller

## Technique Context

Password spraying (T1110.003) is a credential access technique where attackers attempt a small number of commonly used passwords against many user accounts to avoid account lockouts. Unlike brute force attacks that target one account with many passwords, password spraying distributes login attempts across multiple accounts with a few passwords. This technique is particularly effective against organizations with weak password policies and is commonly used in the initial access phase of attacks.

The detection community focuses on identifying patterns of authentication failures across multiple accounts from single sources, unusual LDAP bind operations, PowerShell-based credential testing scripts, and network connections to domain controllers on LDAP ports. This specific variant uses .NET System.DirectoryServices.Protocols classes to perform LDAP authentication attempts directly against the domain controller.

## What This Dataset Contains

This dataset captures a PowerShell-based password spraying attack using LDAP authentication via System.DirectoryServices.Protocols. The attack script queries Active Directory for all enabled user accounts using the LDAP filter `(&(sAMAccountType=805306368)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))` and then attempts to authenticate each user with the password "P@ssw0rd!" using NTLM authentication.

Key telemetry includes:

**PowerShell Script Block Logging (EID 4104)**: The complete password spraying script is captured, showing the authentication method validation, AD user enumeration via `Get-ADUser`, and the LDAP connection loop using `System.DirectoryServices.Protocols.LdapConnection` with NTLM authentication type.

**PowerShell Command Invocation (EID 4103)**: Individual cmdlet executions show `New-Object` commands creating `System.DirectoryServices.Protocols.LdapDirectoryIdentifier`, `System.Net.NetworkCredential` objects with the cleartext password "P@ssw0rd!", and `System.DirectoryServices.Protocols.LdapConnection` objects. Failed authentication attempts generate "The supplied credential is invalid" error messages.

**Process Creation (Security EID 4688 & Sysmon EID 1)**: Shows the child PowerShell process (PID 33260) spawned to execute the password spraying script with the full command line including the embedded attack code.

**Sysmon Process Access (EID 10)**: Documents PowerShell accessing both the whoami.exe process and the child PowerShell process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks network-level evidence of the LDAP authentication attempts. There are no Sysmon Network Connection (EID 3) events showing connections to the domain controller on port 389, likely due to the sysmon-modular configuration filtering. Additionally, there are no domain controller-side authentication logs that would show the failed LDAP bind attempts from the perspective of the target system.

The PowerShell logging shows error messages indicating credential failures, but there are no Security event logs documenting failed authentication attempts (EID 4625) from the domain controller's perspective. The technique appears to execute without generating detectable network telemetry on the attacking host, making the PowerShell script block logging the primary detection artifact.

## Assessment

This dataset provides excellent coverage of PowerShell-based password spraying techniques from a host-based detection perspective. The PowerShell script block logging (EID 4104) captures the complete attack methodology, including credential objects with cleartext passwords, LDAP connection parameters, and error handling. The command invocation logs (EID 4103) provide granular visibility into individual object instantiations and method calls.

However, the dataset would be significantly stronger with network telemetry showing LDAP connections to domain controllers and corresponding authentication failure logs from the target systems. The lack of network connection events limits the ability to detect this technique through network-based monitoring, making organizations heavily dependent on PowerShell logging for detection.

## Detection Opportunities Present in This Data

1. **PowerShell script blocks containing System.DirectoryServices.Protocols classes** - EID 4104 events with "System.DirectoryServices.Protocols.LdapConnection" and "System.DirectoryServices.Protocols.LdapDirectoryIdentifier" indicate potential LDAP-based authentication testing

2. **PowerShell cmdlet invocations creating multiple NetworkCredential objects** - EID 4103 events showing repeated "New-Object" commands with "System.Net.NetworkCredential" and consistent password values across multiple user contexts

3. **PowerShell scripts performing AD user enumeration followed by authentication loops** - Script blocks containing "Get-ADUser" with specific LDAP filters followed by "Foreach-Object" loops creating credential objects

4. **Child PowerShell processes with embedded credential testing code** - Process creation events (EID 4688/EID 1) showing PowerShell command lines containing authentication-related .NET classes and credential testing logic

5. **PowerShell error messages indicating authentication failures** - Command invocation logs showing "The supplied credential is invalid" messages in Write-Host commands, particularly when associated with credential testing scripts

6. **Process access patterns from PowerShell to multiple child processes** - Sysmon EID 10 events showing PowerShell accessing spawned processes with full access rights during credential testing operations
