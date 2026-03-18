# T1069.002-11: Domain Groups — Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)

## Technique Context

T1069.002 (Domain Groups) involves adversaries attempting to find domain-level groups and permission settings. This specific test uses PowerShell's `Get-ADUser` cmdlet with UserAccountControl filtering to identify accounts vulnerable to AS-REP Roasting attacks. AS-REP Roasting targets user accounts that have Kerberos pre-authentication disabled (UserAccountControl flag 4194304), allowing attackers to request authentication service replies without providing valid credentials and crack the resulting hashes offline.

The detection community focuses on monitoring Active Directory enumeration activities, particularly PowerShell-based queries using AD cmdlets, LDAP searches with specific filters, and processes accessing domain controller services for reconnaissance. UserAccountControl-based filtering is a strong indicator of targeted enumeration for specific attack vectors.

## What This Dataset Contains

The dataset captures a complete PowerShell-based Active Directory enumeration sequence. Security event 4688 shows the key command execution: `"powershell.exe" & {Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name}`. This command specifically queries for user accounts with the DONT_REQUIRE_PREAUTH flag set, making them vulnerable to AS-REP Roasting.

The PowerShell channel contains script block logging (EID 4104) capturing the exact enumeration command: `Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name`. Sysmon provides comprehensive process telemetry including process creation (EID 1) with full command lines, image loads (EID 7) showing PowerShell and .NET runtime loading, and process access events (EID 10) showing PowerShell accessing child processes.

The dataset shows standard PowerShell test framework activity with `Set-ExecutionPolicy Bypass` commands in the PowerShell operational log, followed by the actual enumeration command execution. Process chains show the parent PowerShell spawning child processes including `whoami.exe` and another PowerShell instance executing the AD query.

## What This Dataset Does Not Contain

The dataset lacks network telemetry showing the actual LDAP queries to domain controllers, as Sysmon's network connection monitoring may not capture local domain queries or they were filtered by the configuration. There are no Kerberos-related events (4768, 4769) that would show the authentication requests to the domain controller during the AD enumeration.

The dataset doesn't contain any blocked execution events, suggesting Windows Defender allowed the enumeration to proceed normally. There's also no evidence of the actual results returned by the Get-ADUser query - we can see the command executed but not whether any vulnerable accounts were discovered or what data was returned to the attacker.

## Assessment

This dataset provides excellent telemetry for detecting Active Directory enumeration activities focused on AS-REP Roasting preparation. The combination of Security 4688 command-line logging, PowerShell script block logging, and Sysmon process creation events gives multiple detection opportunities for this specific enumeration pattern. The UserAccountControl flag value (4194304) in the command line is a high-fidelity indicator of AS-REP Roasting reconnaissance.

The telemetry quality is strong for host-based detection but would benefit from network-level LDAP query monitoring and domain controller-side logging to provide complete coverage of the enumeration activity. The clear command-line artifacts make this an excellent dataset for training detection rules focused on PowerShell-based AD reconnaissance.

## Detection Opportunities Present in This Data

1. Command-line detection for PowerShell executing Get-ADUser with UserAccountControl bitwise operations, specifically targeting flag 4194304 (DONT_REQUIRE_PREAUTH)
2. PowerShell script block logging detection for AD enumeration commands containing "useraccountcontrol -band" patterns
3. Process creation monitoring for PowerShell spawning with command lines containing Active Directory cmdlets and suspicious filtering parameters
4. Behavioral detection for rapid succession of PowerShell processes executing AD-related commands from the same parent process
5. PowerShell module loading detection when System.Management.Automation and AD-related assemblies are loaded in suspicious contexts
6. Process access pattern detection showing PowerShell accessing multiple child processes during enumeration activities
7. Named pipe creation monitoring for PowerShell host pipes during AD enumeration sessions
