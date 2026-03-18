# T1550.003-2: Pass the Ticket — Rubeus Kerberos Pass the Ticket

## Technique Context

Pass the Ticket (T1550.003) involves stealing or forging Kerberos tickets and injecting them into a session to authenticate as another user or access resources without credentials. Rubeus is a .NET Kerberos toolkit that implements TGT and TGS request/injection operations. This test uses PsExec to run Rubeus in a separate process context: first requesting a TGT for Administrator using a known password (`asktgt`), then requesting a TGS for CIFS access (`asktgs`), and finally injecting the ticket into the current logon session (`/ptt`).

## What This Dataset Contains

The complete Rubeus/PsExec command chain is captured in both Security 4688 and Sysmon EID 1 as the powershell.exe command line:

> `& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" -accepteula \\localhost -w c:\ -c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus.exe" asktgt /user:Administrator /password:Password /domain:$Env:USERDOMAIN /outfile:ticket.kirbi`

The script block logging (EID 4104) records the complete multi-step sequence: `asktgt`, `Move-Item` to retrieve the output ticket from `\\localhost\c$\ticket.kirbi`, `asktgs /service:cifs/localhost /ticket:ticket.kirbi /ptt`, cleanup via `Remove-Item`, and `rubeus.exe purge`. This provides full attack plan visibility.

Despite the command being recorded, neither `PsExec.exe` nor `rubeus.exe` appear as process creations in the Sysmon EID 1 log or as loaded images in EID 7. The Sysmon ProcessCreate filter uses include-mode rules targeting known-suspicious patterns; neither binary name matches the filter. Security 4688 likewise shows only `whoami.exe` and `powershell.exe` process creations. The Security log contains two EID 4703 (Token Right Adjusted) events showing `lsass.exe` enabling `SeCreateTokenPrivilege` and `SeAssignPrimaryTokenPrivilege`, which are consistent with Kerberos ticket operations.

The 36 Sysmon events are: 26 EID 7 image loads (three PowerShell instances loading .NET CLR and Defender DLLs), 3 EID 17 named pipe creates for three distinct PowerShell processes, 3 EID 11 file creates (PowerShell profile data), and 2 EID 10 ProcessAccess events (powershell.exe opening whoami.exe and the attack powershell.exe with full access).

## What This Dataset Does Not Contain (and Why)

There are no Kerberos-specific Security events (4768 TGT request, 4769 TGS request, 4770 TGS renewal, 4771 AS failure) because the audit policy has `kerberos: success_and_failure` scoped to Domain Controller logs — these events are generated on the DC, not the workstation. There is no direct evidence of ticket injection (which would appear as a 4627 or anomalous logon on the target) because no DC-side collection is included in this dataset. PsExec and Rubeus process creations are absent from Sysmon because the include-mode filter does not cover those binary names.

## Assessment

This dataset's primary detection value lies in the PowerShell command line and script block logs, which fully document the Rubeus attack chain. The lsass.exe token privilege adjustments provide a secondary behavioral indicator. The absence of Rubeus and PsExec from Sysmon process creation is a meaningful documentation of Sysmon include-mode filtering gaps: binary names not in the LOLBin-oriented include list will not appear in Sysmon EID 1, and Security 4688 captures the parent powershell.exe launch but the child PsExec and Rubeus processes are not logged because Sysmon missed them and the audit policy context here does not attribute them distinctly.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block**: The full Rubeus command sequence — `asktgt`, `asktgs /ptt`, SMB UNC path for ticket retrieval, and `purge` — is logged verbatim. The binary path `C:\AtomicRedTeam\...\ExternalPayloads\rubeus.exe` is explicit.
- **Security 4688 command line**: The powershell.exe invocation with the PsExec and Rubeus full command arguments is captured, including `/outfile:ticket.kirbi` and `/ptt`.
- **Security 4703 Token Right Adjusted for lsass.exe**: `SeCreateTokenPrivilege` and `SeAssignPrimaryTokenPrivilege` being enabled for lsass.exe is consistent with Kerberos ticket issuance activity.
- **Three distinct PowerShell processes** (Sysmon EID 17 pipe names): Multiple short-lived PowerShell instances in rapid succession is indicative of ART-style test framework execution but also of chained attack steps.
- **UNC path `\\localhost\c$\ticket.kirbi`**: Self-referential SMB access to retrieve a Kerberos ticket from disk is an unusual pattern detectable in file access or process command-line logs.
