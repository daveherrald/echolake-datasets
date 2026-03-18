# T1059.001-12: PowerShell — PowerShell Session Creation and Use (New-PSSession / WinRM)

## Technique Context

T1059.001 PowerShell execution extends naturally into lateral movement and remote execution through PowerShell Remoting. `New-PSSession` creates a persistent PowerShell session on a remote computer using WinRM (Windows Remote Management) over port 5985 (HTTP) or 5986 (HTTPS). Once established, an attacker can use `Invoke-Command` to run arbitrary PowerShell in the remote session with the credentials of the originating process or with explicitly supplied credentials.

This is a significant escalation from local PowerShell execution. PowerShell Remoting is a legitimate administrative capability built into Windows since PowerShell 2.0, which makes it difficult to block without breaking many enterprise operations. Attackers frequently use it for lateral movement after gaining initial access — connecting from a compromised workstation to a domain controller, file server, or other high-value targets. The authentication traffic (Kerberos or NTLM), network connections on port 5985, and the characteristic `wsmprovhost.exe` process on the remote end all appear in telemetry.

This test uses `New-PSSession -ComputerName $env:COMPUTERNAME` — connecting to the local machine — to demonstrate the remoting mechanism without requiring network access to a second host. In the defended version, the test fails with "Access is denied" due to WinRM configuration restrictions. In this undefended run, the connection succeeds, generating the full authentication event chain, network connections, and `wsmprovhost.exe` spawning that represents a successful remote PowerShell session. This is a meaningful difference: the defended dataset shows an access failure, while this dataset shows a successful session establishment.

## What This Dataset Contains

The dataset spans ten seconds (2026-03-14T23:18:34Z to 23:18:44Z) — longer than most other tests — and records 201 events across three channels: Sysmon (49), PowerShell (132), and Security (20).

**Security EID 4688** captures the complete process creation chain. The key command line for the PowerShell child process:

```
"powershell.exe" & {New-PSSession -ComputerName $env:COMPUTERNAME
Test-Connection $env:COMPUTERNAME
Set-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use -Value "T1086 PowerShell Session Creation and Use"
Get-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
Remove-Item -Force $env:TEMP\T1086_PowerShell_Session_Creation_and_Use}
```

This shows the complete test sequence: create session, test connectivity, write a file, read it back, and clean up. The file `T1086_PowerShell_Session_Creation_and_Use` in `%TEMP%` serves as evidence of successful remote execution.

**Security EID 4688 also captures `C:\Windows\System32\wsmprovhost.exe -Embedding`**. This is the WinRM Provider Host process that spawns on the receiving end of a PowerShell Remoting connection. In this loopback scenario it appears on the same machine, but in a real lateral movement scenario `wsmprovhost.exe -Embedding` on the target system is the signature of incoming PowerShell remoting.

**Security EID 4624 (Logon), EID 4648 (Explicit Credential Logon), and EID 4672 (Special Privileges Assigned)** each appear multiple times. The EID 4624 events show:
- `TargetUserName: ACME-WS06$` (the machine account)
- `LogonType: 3` (network logon)
- `IpAddress: fe80::5e9:92bc:73ee:45d4` (IPv6 link-local address of the loopback interface)

The EID 4648 events show:
- `SubjectUserName: ACME-WS06$`
- `TargetUserName: ACME-WS06$`
- `TargetServerName: ACME-WS06.acme.local`
- `ProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

This authentication sequence — the machine account authenticating to itself over the loopback — is the specific artifact of loopback WinRM remoting. In a real attack the source and destination account names would differ, and the IP address would be a remote host rather than loopback.

**EID 4672** shows the machine account being assigned sensitive privileges: `SeSecurityPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeDebugPrivilege`, `SeSystemEnvironmentPrivilege`, and others. These are the privileges associated with a SYSTEM-level machine account logon via WinRM.

**Sysmon EID 3 (NetworkConnect)** contributes 7 events. These are the WinRM connections from the PowerShell client to the WinRM listener on port 5985, all over IPv6 loopback. In a real lateral movement scenario these would show connections to the target host's IP.

**Sysmon EID 22 (DNSQuery)** shows 4 events. The test calls `Test-Connection $env:COMPUTERNAME` and `New-PSSession -ComputerName $env:COMPUTERNAME`, both of which trigger DNS resolution for the local hostname `ACME-WS06.acme.local`. DNS queries for hostnames preceding WinRM connections are part of the normal session establishment flow.

**Sysmon EID 17 (PipeCreate)** shows 4 events — more than other tests — reflecting the multiple PowerShell session pipes created for the remoting session.

**Sysmon EID 11 (FileCreate)** shows 4 events. The temp file `T1086_PowerShell_Session_Creation_and_Use` written during remote session execution appears here.

**PowerShell EID 4104** contributes 98 events. Critically, this includes **EID 8197, 8196, 8193, 8194, 8195** and **EID 12039** — WinRM-specific event IDs from the `Microsoft-Windows-WinRM` provider. EID 8197 records outbound connection requests; EID 8193/8194/8195 record session initialization; EID 12039 records the remote host name. These WinRM operational events appear in the PowerShell channel collection because they were captured alongside PowerShell events.

Compared to the defended version (35 sysmon, 16 security, 77 PowerShell), this undefended run shows significantly more events: 49 sysmon (vs. 35), 20 security (vs. 16), and 132 PowerShell (vs. 77). The larger counts directly reflect successful session establishment — the defended version failed at the `New-PSSession` call, so no WinRM authentication chain, no `wsmprovhost.exe`, and no remote execution artifacts appear there.

## What This Dataset Does Not Contain

No Sysmon EID 1 event for `wsmprovhost.exe` appears in samples, though the process is confirmed via Security EID 4688. The sysmon-modular include-mode filter may not capture `wsmprovhost.exe` spawns.

No events from the remote session itself (commands executed inside the PSSession). Since this test uses loopback, all events are local — in a real lateral movement scenario, the remote host's telemetry would need to be analyzed separately.

No EID 4634 (Logoff) events appear in samples despite being present in the EID breakdown (3 events). These represent the session teardown.

## Assessment

This dataset provides the most network-rich evidence of any test in the T1059.001 group. The successful WinRM session establishment produces a distinctive combination of artifacts: authentication events (4624, 4648, 4672), network connections to port 5985 (EID 3), DNS queries (EID 22), `wsmprovhost.exe` process creation, WinRM operational events (EID 8193-8197, 12039), and file creation from the remote session. Together these form a complete picture of what PowerShell Remoting looks like in telemetry — valuable for building detections that look beyond just process creation to the full authentication and network flow.

The comparison with the defended version is particularly instructive: the defended dataset shows an access failure, this dataset shows a success. Detection engineers can use both to understand what "partial vs. complete" WinRM attack patterns look like.

## Detection Opportunities Present in This Data

1. **wsmprovhost.exe -Embedding process creation**: Security EID 4688 shows `wsmprovhost.exe -Embedding` spawned by WinRM infrastructure. Any `wsmprovhost.exe` process with the `-Embedding` flag indicates an incoming PowerShell remoting connection. On the target host, this is the primary indicator of active remoting sessions.

2. **Security EID 4648 with process name powershell.exe targeting a remote system**: The explicit credential logon events (`SubjectUserName: ACME-WS06$`, `TargetServerName: ACME-WS06.acme.local`, `ProcessName: ...powershell.exe`) identify PowerShell as the authentication source. In real lateral movement, the source and target system names would differ, making this pattern a reliable alert.

3. **Sysmon EID 3 (NetworkConnect) from powershell.exe to port 5985 or 5986**: WinRM uses port 5985 (HTTP) and 5986 (HTTPS). Network connections from `powershell.exe` to these ports in environments where WinRM remoting is not routine administration are anomalous.

4. **Sysmon EID 22 (DNS) for hostnames immediately preceding port 5985 connections**: The pattern of DNS resolution for a hostname followed within milliseconds by a TCP connection to port 5985 on the resolved IP is the natural flow of `New-PSSession -ComputerName`. Correlating EID 22 and EID 3 events with this timing and port pattern identifies WinRM session initiation.

5. **Security EID 4672 with machine account and SeDebugPrivilege via WinRM**: The special privileges assigned to `ACME-WS06$` via the WinRM logon include `SeDebugPrivilege`. Machine account WinRM logons with debug privileges are unusual and indicate SYSTEM-context remoting.

6. **WinRM operational events (EID 8193-8197, 12039) combined with preceding PowerShell process creation**: The presence of WinRM session events in close temporal proximity to a PowerShell process that was spawned by a scripting test framework identifies the automation context. These events fire on both success and failure — correlating them with the outcome (successful `wsmprovhost.exe` spawn vs. access denied) provides state-aware detection.
