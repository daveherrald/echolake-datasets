# T1207-1: Rogue Domain Controller — DCShadow (Active Directory)

## Technique Context

T1207 (Rogue Domain Controller) describes one of the most sophisticated Active Directory attacks available to an adversary with sufficient privilege: DCShadow. Developed by Benjamin Delpy and Vincent Le Toux and implemented in Mimikatz, DCShadow allows an attacker who has achieved SYSTEM-level privilege on a domain-joined machine to temporarily register that machine as a domain controller, then inject arbitrary changes into Active Directory through the normal DC replication protocol. Because the changes arrive via legitimate AD replication, many security monitoring tools — including domain controller audit logs — may not record them as unauthorized modifications.

The technique requires: SYSTEM privileges on the attacker's machine, network access to the real domain controllers, and the ability to register SPN (Service Principal Name) entries for DC replication services. Detection focuses on unexpected domain controller registrations in the `CN=Sites,CN=Configuration` partition, unusual DRS (Directory Replication Service) traffic from non-DC machines, and executions of Mimikatz or similar tools with `lsadump::dcshadow` arguments.

## What This Dataset Contains

This dataset captures the DCShadow attempt in an undefended environment. Unlike the defended dataset where Defender suppressed the process chain, this run produces richer telemetry showing the full attack structure.

Security EID 4688 records the critical attacker command chain. First, a PowerShell process (PID 0x3c30) is created with the full DCShadow setup script:

`"powershell.exe" & {# starting fake DC server, as SYSTEM (required) $dc_output_file = "C:\AtomicRedTeam\atomics\..\ExternalPayloads\art-T1207-mimikatz-DC.log" Remove-Item $dc_output_file -ErrorAction Ignore $mimikatzParam = "\"log $dc_output_file\"" \"lsadump::dcshadow /object:bruce.wayne /attribute:badpwdcount /value:9999\" ...`

The script attempts to register a fake DC server and prepare Mimikatz to push the AD object modification for `bruce.wayne` — setting the `badpwdcount` attribute to `9999`. This object modification target (a realistic-looking domain user `bruce.wayne`) is the specific AD change DCShadow would inject.

Second, Security EID 4688 records `cmd.exe` (PID 0x462c, child of PowerShell 0x3c30) executing:

`"C:\Windows\system32\cmd.exe" /c 'C:\AtomicRedTeam\atomics\..\ExternalPayloads\PSTools\PsExec.exe' /accepteula -d -s C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe "log C:\AtomicRedTeam\atomics\..\ExternalPayloads\art-T1207-mimikatz-DC.log" "lsadump::dcshadow /object:bruce.wayne /attribute:badpwdcount /value:9999" "exit"`

This is the Mimikatz invocation via PsExec with full arguments visible in the Security log. The `lsadump::dcshadow /object:bruce.wayne /attribute:badpwdcount /value:9999` argument string is the DCShadow push command — modifying the `badpwdcount` attribute on the `bruce.wayne` user object. A fifth Security EID 4688 event records a cleanup PowerShell process: `"powershell.exe" & {Stop-Process -Name "mimikatz" -Force -ErrorAction Ignore}`.

The Sysmon channel provides 35 events: 22 EID 7, 5 EID 1, 4 EID 10, 2 EID 17, and 2 EID 11. Sysmon EID 1 captures the PowerShell process tagged with `RuleName: technique_id=T1134,technique_name=Access Token Manipulation`, reflecting the privilege escalation component of the DCShadow setup. Sysmon EID 7 captures the .NET CLR and PowerShell DLL loads into the process chain.

The PowerShell channel records 114 events (113 EID 4104, 1 EID 4103), predominantly test framework boilerplate with the cleanup block `try { Invoke-AtomicTest T1207 -TestNumbers 1 -Cleanup -Confirm:$false | Out-Null } catch {}`.

## What This Dataset Does Not Contain

No process creation events for `PsExec.exe` or `mimikatz.exe` appear in either the Security or Sysmon channels. While the cmd.exe process (0x462c) is created and visible, it exits with status code `0x1` (failure), indicating PsExec was not found at the specified path or execution was blocked by OS security mechanisms short of Defender. The `ExternalPayloads` directory structure expected by the ART test (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\PSTools\PsExec.exe` and `...\mimikatz\x64\mimikatz.exe`) was likely not fully populated on this test system.

No LDAP traffic, DC replication events, or domain controller-side artifacts are present — these would require DC-side monitoring and are outside the scope of this endpoint-focused dataset. No Sysmon EID 3 (network connection) events appear, consistent with the actual DCShadow replication not occurring.

In the defended dataset (Sysmon: 38, Security: 13, PowerShell: 54), the same execution failure occurred. However, the undefended dataset captures the full PowerShell script content and the complete cmd.exe command with all Mimikatz arguments in the Security audit log — the defended dataset had fewer Security events (13 vs. 5 here, which is actually fewer in the undefended run). This reflects the fact that Defender's presence triggered additional process creation monitoring in the defended run.

## Assessment

Even though the DCShadow execution did not complete (Mimikatz was not present), this dataset contains some of the most specific and actionable threat intelligence artifacts in this batch. The Security EID 4688 command line for the cmd.exe process exposes:
- The full PsExec path (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\PSTools\PsExec.exe`)
- The full Mimikatz path (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe`)
- The exact DCShadow command (`lsadump::dcshadow /object:bruce.wayne /attribute:badpwdcount /value:9999`)

The combination of `PsExec` with `-s` (SYSTEM) and `mimikatz.exe` with `lsadump::dcshadow` arguments is, by itself, a definitive detection signal regardless of whether the execution succeeds. Similarly, the PowerShell command line referencing `lsadump::dcshadow` in a string argument is uniquely specific.

The Sysmon EID 1 tagging of the PowerShell process as `T1134 Access Token Manipulation` reflects the privilege manipulation inherent in DCShadow's SYSTEM requirement — an important detection layer that fires even when the downstream Mimikatz execution is missing.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `mimikatz.exe` appearing as an argument in a `PsExec` command line is an unambiguous high-severity detection; the string `lsadump::dcshadow` in any process command line is a definitive DCShadow indicator
- **Security EID 4688**: `PsExec.exe /accepteula -d -s` executing any binary is a high-risk privilege escalation pattern; the combination with Mimikatz paths is critical severity
- **Security EID 4688 / Sysmon EID 1**: PowerShell command lines referencing `ExternalPayloads` directory paths containing `mimikatz` — the directory name itself is distinctive of ART and similar offensive tooling setups
- **Sysmon EID 1**: PowerShell process tagged `technique_id=T1134,technique_name=Access Token Manipulation` fires even before Mimikatz is invoked, providing early detection of the privilege escalation intent
- **PowerShell EID 4104**: Script block content containing `lsadump::dcshadow` and `bruce.wayne /attribute:badpwdcount` — these strings appear in in-memory script blocks and would be captured by any AMSI integration
- **File system**: The log output file path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\art-T1207-mimikatz-DC.log` — the presence of this file after an attack would confirm DCShadow was attempted even if real-time logging missed the process execution
- **AD replication monitoring (not in this dataset)**: In a successful DCShadow attack, unexpected DRS replication requests from a non-DC workstation would appear in AD DS event logs (EID 4929, EID 4932) on the legitimate domain controllers — these are the ground-truth detection artifacts for DCShadow and are not captured in this endpoint-focused dataset
