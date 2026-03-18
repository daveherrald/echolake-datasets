# T1003.006-1: DCSync — DCSync via mimikatz

## Technique Context

DCSync (T1003.006) exploits the Active Directory replication protocol to extract credential hashes from domain controllers without ever accessing their filesystems or running code on them. An attacker with sufficient privileges — typically Domain Admin or an account granted "Replicating Directory Changes All" — can impersonate a domain controller and request that a real DC replicate credential data, including NTLM hashes and Kerberos keys, for any account in the domain. The attack uses the Microsoft Directory Replication Service (MS-DRSR) protocol over LDAP/RPC.

Mimikatz implements this via `lsadump::dcsync`, which takes a `/domain` parameter and a `/user` parameter specifying which account to extract. Targeting `krbtgt` — as this test does — is particularly significant because the krbtgt hash is the foundation for Golden Ticket attacks. With that hash, an attacker can forge Kerberos TGTs for any account in the domain indefinitely (until krbtgt is reset twice).

The detection community has good coverage of DCSync: Windows DCs log Directory Service replication events (EID 4662) when a non-DC account requests replication, and Sysmon network telemetry can capture the LDAP/RPC connections to port 389 or 445. In the defended version, Defender killed mimikatz before it could initiate the replication request, so none of the domain controller-side telemetry appeared. With Defender disabled, mimikatz runs and the replication traffic should occur — though this dataset captures workstation-side telemetry only, not DC-side events.

## What This Dataset Contains

The Security channel's four EID 4688 events are the clearest evidence in this dataset. The most important is:

```
"cmd.exe" /c %tmp%\mimikatz\x64\mimikatz.exe "lsadump::dcsync /domain:%userdnsdomain% /user:krbtgt@%userdnsdomain%" "exit"
```

This command line (with environment variables unexpanded in the log — `%userdnsdomain%` would resolve to `acme.local`) is spawned by PowerShell (PID `0x614`). The unresolved environment variables appear because cmd.exe expands them at runtime, after process creation is logged. The defended dataset showed this same command line but the process exited with status `0xC0000022` (ACCESS_DENIED). In this undefended run, mimikatz can actually execute.

Sysmon EID 17 captures a named pipe creation: `\PSHost.134180020468157513.1556.DefaultAppDomain.powershell` from `powershell.exe` (PID 1556, running as `NT AUTHORITY\SYSTEM`) — this is the PowerShell test framework establishing its IPC channel.

Sysmon EID 10 (ProcessAccess) shows PowerShell (PID 1556) accessing `whoami.exe` (PID 5256) with `GrantedAccess: 0x1fffff` (full access). This access pattern is the Atomic Red Team test framework doing pre/post-execution verification.

Sysmon EID 1 for `whoami.exe` is tagged with rule `technique_id=T1033,technique_name=System Owner/User Discovery`, confirming the test framework runs a user discovery check before executing the main technique.

Compared to the defended version (37 sysmon, 15 security, 41 PowerShell), the undefended run is comparable in size (45 sysmon, 4 security, 104 PowerShell). The security channel is smaller here because the defended version had privilege escalation events (EID 4703) that don't appear in the samples here. The PowerShell event count increased from 41 to 104, suggesting more internal PowerShell activity during the undefended execution.

## What This Dataset Does Not Contain

This dataset captures workstation-side telemetry only. The most important DCSync evidence — DC-side Directory Service replication events (Security EID 4662, "An operation was performed on an object") from the domain controller at `ACME-DC01` — is not present. Those events would show the account `ACME-WS06$` requesting replication with unusual object access flags (`0x100` for Replicating Directory Changes).

There are no Sysmon EID 3 (network connection) events showing mimikatz making LDAP or RPC connections to the domain controller (`192.168.4.10`). These should theoretically appear if mimikatz executed successfully and initiated the replication request, but may have been filtered by the Sysmon configuration or occurred outside the capture window.

The PowerShell channel shows only framework boilerplate — no script block content showing how the ART test framework invoked the technique, and nothing from mimikatz itself since mimikatz is a standalone executable rather than a PowerShell script.

There is no file creation event showing the mimikatz binary being placed in `%tmp%\mimikatz\x64\`, suggesting it was pre-staged before the capture window.

## Assessment

For workstation-side DCSync detection, this dataset offers the command line evidence needed to build process execution detections. The Security EID 4688 event with the `lsadump::dcsync` command line targeting `krbtgt` is unambiguous and represents the single most actionable indicator in the dataset. The absence of DC-side replication events is a genuine limitation — a complete DCSync detection strategy requires correlating workstation-side execution evidence with DC-side directory access logs, which this dataset cannot provide on its own.

## Detection Opportunities Present in This Data

1. Security EID 4688 with a command line containing `mimikatz.exe` and `lsadump::dcsync` is the clearest possible indicator. The specific pattern `lsadump::dcsync /domain: ... /user:krbtgt` is targeting the most sensitive possible account.

2. Sysmon EID 1 showing `cmd.exe` with a command line containing `mimikatz.exe` spawned by PowerShell running as SYSTEM — the parent-child relationship (powershell.exe → cmd.exe → mimikatz.exe) is characteristic of ART-style and real-world execution patterns.

3. The file path `%tmp%\mimikatz\x64\mimikatz.exe` (or variations under user temp directories) as the `NewProcessName` in Security EID 4688 is immediately suspicious regardless of the subcommand.

4. Sysmon EID 10 showing PowerShell accessing `whoami.exe` with `0x1fffff` access rights immediately before spawning a cmd.exe/mimikatz process is a behavioral precursor pattern worth modeling.

5. On the domain controller side (not captured here but essential for complete coverage): Security EID 4662 from a non-DC source with `Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` or `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (the GUIDs for Replicating Directory Changes rights) indicates a successful DCSync request.

6. Network telemetry showing an unexpected workstation establishing TCP connections to port 389 or 445 on a domain controller — particularly from a process like `mimikatz.exe` or an unusual parent process — is a network-layer DCSync indicator that would complement the process execution evidence here.
