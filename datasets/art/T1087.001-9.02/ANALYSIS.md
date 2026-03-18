# T1087.001-9: Local Account — Enumerate all accounts via PowerShell (Local)

## Technique Context

T1087.001 (Account Discovery: Local Account) covers adversary enumeration of local user and group accounts on a compromised system. Knowing local accounts helps attackers identify local administrators for lateral movement, discover service accounts for credential attacks, and understand the system's user population. The ART test here is unusually comprehensive: rather than running a single query, it executes an eight-command sequence covering every common local account enumeration method:

```
net user
get-localuser
get-localgroupmember -group Users
cmdkey.exe /list
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-localgroup
net localgroup
```

This mirrors real attacker behavior, where multiple redundant commands are run in sequence to ensure comprehensive coverage regardless of which methods might be restricted or logged. `cmdkey.exe /list` is particularly notable — it enumerates stored Windows credentials in Credential Manager, going beyond account discovery into credential access territory.

## What This Dataset Contains

This dataset covers a 4-second window (2026-03-14T23:33:51Z–23:33:55Z) — longer than simpler tests due to the multi-command execution.

**Process execution chain**: Sysmon EID 1 records `whoami.exe` (PID 2304) at 23:33:52, then the main PowerShell process (PID 6844) at 23:33:53 with the full command line clearly showing all eight enumeration commands. Sysmon tags this with `technique_id=T1087.001,technique_name=Local Account`. Multiple additional child processes follow — `net.exe`, `net1.exe`, `cmdkey.exe`, and additional `whoami.exe` — captured across the 9 total EID 1 events in this dataset.

**Security EID 4799 (21 events)**: This is the richest source of technique evidence. EID 4799 fires when a security-enabled local group membership is enumerated. The 21 events capture `get-localgroupmember -group Users` and `net localgroup` iterating through local groups including:
- `Users` (S-1-5-32-545)
- `Access Control Assistance Operators` (S-1-5-32-579)
- and many more built-in local groups

All 21 EID 4799 events show `powershell.exe` as the querying process.

**Security EID 4688 (9 events)**: Process creation events cover the eight-command sequence's subprocess launches. These confirm `net.exe user`, `net1.exe user`, `cmdkey.exe /list`, `net.exe localgroup`, and `net1.exe localgroup` as distinct process creation events.

**Security EID 5379 (1 event)**: This is the most sensitive event in the dataset. EID 5379 fires when `Credential Manager credentials were read`, recording `Read Operation: Enumerate Credentials` attributed to `NT AUTHORITY\SYSTEM`. This single event documents that `cmdkey.exe /list` successfully enumerated the Credential Manager — crossing into credential access territory beyond pure account discovery.

**Sysmon EID 10 (7 events)**: Process access events for multiple parent-child access patterns. Seven events reflect the PowerShell parent accessing the multiple child processes.

**Sysmon EID 11 (1 event)**: The routine `StartupProfileData-NonInteractive` PS profile cache write.

**PowerShell script block logging**: 95 EID 4104 events and 6 EID 4103 events (101 total). The EID 4103 module pipeline events capture the PowerShell-native commands (`get-localuser`, `get-localgroupmember`, `get-localgroup`) in detail.

Comparing to the defended dataset (55 sysmon, 21 security, 43 powershell): the undefended run shows 45 sysmon, 31 security, and 101 powershell events. The security event count dramatically increased (31 vs 21), because the eight-command sequence generated more group enumeration events (21 × EID 4799 vs fewer in the defended run). The powershell count increase (101 vs 43) reflects the actual execution completing without interruption.

## What This Dataset Does Not Contain

The actual account information discovered — the list of local users, group memberships, and stored credentials — does not appear in any event. `net user` output, `get-localuser` results, and the contents of `ls C:\Users\` are visible only to whoever received PowerShell's console output. The Credential Manager enumeration (EID 5379) confirms the query occurred but does not list which credentials were found.

There are no domain queries or network events; all enumeration is purely local to ACME-WS06.

## Assessment

This is one of the most telemetry-rich datasets in this batch. The combination of Security EID 4799 (group enumeration) and EID 5379 (credential read) alongside process creation events provides strong, multi-source evidence of systematic local account discovery. The full 8-command sequence is visible in the PowerShell EID 1 command line, making intent unambiguous.

The EID 5379 event is particularly valuable: it documents credential access concurrent with account discovery, showing that attackers who run `cmdkey.exe /list` leave a specific, dedicated audit event rather than hiding within generic process creation records.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: The PowerShell command line contains the entire eight-command enumeration sequence including `cmdkey.exe /list` — one of the clearest combined account discovery + credential access indicators in a single command line. `cmdkey.exe /list` as a child of PowerShell running as SYSTEM is particularly anomalous.

**Security EID 4799 (bulk)**: Twenty-one group membership enumeration events in under 4 seconds from `powershell.exe` running as SYSTEM indicates automated group enumeration. A single `get-localgroupmember -group Users` from an administrative script would generate a few EID 4799 events; 21 events in 4 seconds signals a sweep through all local groups.

**Security EID 5379**: A single credential read enumeration event — `Enumerate Credentials` by `NT AUTHORITY\SYSTEM` — documents that `cmdkey.exe /list` ran successfully. This event is high-fidelity for the credential access component of this technique.

**PowerShell EID 4103**: Six module pipeline events capture the `get-localuser`, `get-localgroupmember`, and `get-localgroup` cmdlet executions with their parameters. These provide cleaner, structured records than the raw command line.

**Multi-command sequence**: The process creation chain — `net.exe`, `net1.exe`, `cmdkey.exe`, all in rapid succession from the same parent PowerShell — is a reliable indicator of scripted account enumeration regardless of what the PowerShell script block content looks like.
