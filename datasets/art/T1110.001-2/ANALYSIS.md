# T1110.001-2: Password Guessing — NTLM or Kerberos

## Technique Context

T1110.001 Password Guessing represents one of the most common credential-based attack techniques, where adversaries attempt to gain unauthorized access by systematically trying different passwords against user accounts. This specific test focuses on LDAP-based brute force attacks against Active Directory domain controllers, simulating how attackers might target domain credentials using either NTLM or Kerberos authentication. The detection community typically monitors for patterns like multiple failed authentication attempts, unusual LDAP connection patterns, and explicit credential usage events. This technique is particularly valuable to defenders because it generates predictable authentication telemetry that can be used to build robust detection rules for credential-based attacks.

## What This Dataset Contains

This dataset captures a PowerShell-based LDAP brute force attack targeting the domain controller ACME-DC01.acme.local. The attack script uses `System.DirectoryServices.Protocols.LdapConnection` with NTLM authentication to iterate through a password list from `C:\AtomicRedTeam\atomics\T1110.001\src\passwords.txt`.

The core attack is visible in Security event ID 4688 with the full command line: `"powershell.exe" & {if ("NTLM".ToLower() -NotIn @("ntlm","kerberos")) { Write-Host "Only 'NTLM' and 'Kerberos' auth methods are supported" exit 1 } [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null $di = new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier("$env:UserDnsDomain",389) $passwordList = Get-Content -Path "C:\AtomicRedTeam\atomics\T1110.001\src\passwords.txt" foreach ($password in $passwordList){ $credz = new-object System.Net.NetworkCredential("$ENV:USERNAME", $password, "$env:UserDnsDomain") $conn = new-object System.DirectoryServices.Protocols.LdapConnection($di, $credz, [System.DirectoryServices.Protocols.AuthType]::NTLM) try { Write-Host " [-] Attempting ${password} on account $ENV:USERNAME." $conn.bind() Write-Host " [!] $ENV:USERNAME:${password} are valid credentials!" } catch { Write-Host $_.Exception.Message } } Write-Host "End of bruteforce"}`

The Security channel contains 100+ Security event ID 4648 (explicit credential usage) events, each showing attempts to authenticate to "ACME-DC01.acme.local" using account "ACME-WS02$" (the machine account). These events demonstrate the iterative password attempts against the domain controller.

Sysmon captures the PowerShell process creation (EID 1), .NET runtime loading (EID 7), and process access events (EID 10) showing PowerShell accessing both whoami.exe and the child PowerShell process. PowerShell script block logging (EID 4104) records the complete attack script and .NET assembly loading.

## What This Dataset Does Not Contain

This dataset is missing several critical elements that would make it more representative of real-world brute force attacks. Most importantly, there are no authentication failure events (Security EID 4625) from the domain controller's perspective, which are typically the primary detection source for password spraying attacks. The dataset only shows the client-side explicit credential usage events (EID 4648) but not the server-side authentication results.

There are no network connection events from Sysmon showing the actual LDAP connections to port 389 on the domain controller, which would normally be captured by Sysmon EID 3. This limits visibility into the network-level indicators of the attack.

The dataset doesn't contain any account lockout events (Security EID 4740) or logon failure reason codes that would indicate whether passwords were actually tested or if the attempts were blocked by account policies.

Additionally, there's no telemetry from the domain controller itself, which would typically generate the authoritative authentication events that defenders rely on for brute force detection.

## Assessment

This dataset provides good visibility into the client-side execution of PowerShell-based LDAP brute force attacks, with excellent process-level telemetry from Sysmon and detailed command-line logging from Security auditing. The PowerShell script block logging captures the complete attack methodology, making it valuable for understanding the technical implementation.

However, the dataset's utility for building comprehensive brute force detections is limited by the absence of server-side authentication telemetry and network connection events. The repeated Security EID 4648 events provide some detection value, but most production environments would focus on authentication failure patterns from domain controllers rather than client-side explicit credential usage.

The dataset is most valuable for detecting the specific PowerShell-based attack technique rather than the broader class of LDAP brute force attempts. Organizations could use this data to build detections around the System.DirectoryServices.Protocols namespace usage in PowerShell and the characteristic command-line patterns.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor PowerShell EID 4104 events for `System.DirectoryServices.Protocols.LdapConnection`, `System.Net.NetworkCredential`, and LDAP brute force script patterns to detect credential attack tools.

2. **Explicit Credential Usage Patterns** - Correlate multiple Security EID 4648 events with the same process ID and target server to identify systematic credential testing, especially when targeting domain controllers.

3. **Suspicious PowerShell Command Lines** - Create detections for Security EID 4688 events containing PowerShell commands that reference LDAP directories, password lists, or credential objects in combination with loop constructs.

4. **Process Access to Authentication Processes** - Monitor Sysmon EID 10 events where PowerShell processes access other authentication-related processes with high privileges (0x1FFFFF), which may indicate credential manipulation.

5. **.NET Assembly Loading for Directory Services** - Track Sysmon EID 7 events showing PowerShell processes loading System.DirectoryServices.Protocols assemblies as an early indicator of LDAP-based attacks.

6. **File Access to Password Lists** - Monitor for PowerShell processes accessing files with names containing "password", "wordlist", or similar terms that might indicate credential attack preparation.

7. **Rapid Process Creation from PowerShell** - Detect when PowerShell spawns child PowerShell processes with authentication-related command lines in quick succession, indicating automated credential testing.
