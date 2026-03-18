# T1087.002-9: Domain Account — Domain

## Technique Context

T1087.002 focuses on domain account enumeration, where attackers gather information about user accounts within an Active Directory environment. This technique is critical during the discovery phase of an attack, as adversaries seek to identify high-value targets like domain administrators, service accounts, and other privileged users. The detection community prioritizes monitoring for commands like `net user /domain`, `dsquery`, LDAP queries, and PowerShell Active Directory cmdlets. Domain account enumeration often precedes privilege escalation attempts and lateral movement, making it a key indicator of reconnaissance activity.

## What This Dataset Contains

This dataset captures a PowerShell-based execution of the classic `net user administrator /domain` command to enumerate details about the default domain administrator account. The process chain shows:

1. **PowerShell execution**: Two PowerShell processes (PIDs 28264 and 22496) launched by NT AUTHORITY\SYSTEM
2. **Identity verification**: A `whoami.exe` execution with command line `"C:\Windows\system32\whoami.exe"`
3. **Domain enumeration**: The core technique via `cmd.exe /c net user administrator /domain` spawning `net.exe` and `net1.exe`

Key telemetry includes:
- **Security 4688** events showing the complete process chain: powershell.exe → cmd.exe → net.exe → net1.exe
- **Sysmon Event 1** capturing process creation with full command lines, including `net user administrator /domain`
- **Sysmon Event 10** showing PowerShell process access to both whoami.exe and cmd.exe with GrantedAccess 0x1FFFFF
- **Sysmon Event 7** documenting .NET CLR and PowerShell module loading
- **PowerShell 4103/4104** events containing only test framework boilerplate (`Set-ExecutionPolicy Bypass`)

The Security events show token elevation type 1 (TokenElevationTypeDefault) indicating full administrative privileges, and all processes run under NT AUTHORITY\SYSTEM context.

## What This Dataset Does Not Contain

The dataset lacks the actual output or results of the domain enumeration command. While we see the process execution telemetry, there are no events capturing what information was returned about the domain administrator account. Additionally, there are no network-level events showing the LDAP queries that `net user /domain` would generate against domain controllers. The PowerShell script block logging contains only execution policy changes rather than any substantive enumeration commands. No file system artifacts related to output redirection or logging are present.

## Assessment

This dataset provides excellent coverage for detection engineering focused on process-based indicators of domain account enumeration. The Security 4688 events with command-line logging and Sysmon Event 1 process creation events offer clear, high-fidelity detection opportunities. The process access events (Sysmon Event 10) add behavioral context showing PowerShell's interaction with spawned processes. However, the dataset would be stronger with network telemetry showing the LDAP queries and any authentication events related to domain controller communication. The absence of actual enumeration output limits understanding of the technique's success.

## Detection Opportunities Present in This Data

1. **Process command line detection**: Monitor Security 4688 and Sysmon Event 1 for command lines containing `net user * /domain` or similar domain enumeration patterns
2. **Process ancestry analysis**: Alert on cmd.exe spawning net.exe with domain enumeration parameters, especially when the parent is PowerShell or other scripting engines
3. **Privileged context enumeration**: Detect domain enumeration commands executed under SYSTEM context, which may indicate automated or scripted reconnaissance
4. **PowerShell process access correlation**: Monitor Sysmon Event 10 where PowerShell accesses net.exe or cmd.exe processes with full access rights (0x1FFFFF)
5. **Behavioral clustering**: Combine whoami.exe execution followed by domain enumeration commands as indicators of discovery phase activity
6. **Net utility abuse detection**: Flag net.exe processes with `/domain` parameters, particularly when spawned by non-interactive sessions or administrative accounts
