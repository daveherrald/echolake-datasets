# T1564-3: Hide Artifacts — Create an "Administrator " User (With a Space on the End)

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) covers methods adversaries use to prevent their
actions from being noticed. This test creates a local Windows user account named
`Administrator ` — the built-in administrator name with a single trailing space appended.
The account is visually indistinguishable from the real `Administrator` account in most
display contexts: Windows Explorer, many third-party tools, and log parsers that trim
whitespace will show the name without the trailing space. An adversary who gains a foothold
as this user can later claim plausible deniability (sessions appear to be the built-in
admin) and may evade detection rules that alert specifically on the string `Administrator`
without accounting for whitespace variants.

The technique requires `New-LocalUser` rather than `net user`, because `net.exe` strips
trailing spaces from account names. This PowerShell-native approach leaves a slightly
different telemetry footprint than `net user` creation.

In the defended variant, this test succeeded — Defender does not block account creation via
PowerShell cmdlets. The defended dataset contained Sysmon process create, DLL load, and
named pipe events, but no account management events (4720, 4726, 4738) because account
management auditing was set to `none`. This undefended dataset adds those account management
events to the Security channel.

## What This Dataset Contains

The dataset spans approximately 3 seconds (17:41:08–17:41:11 UTC) and contains 135 total
events across three channels.

**Security channel (21 events) — EIDs 4688, 4689, 4703, 4720, 4722, 4728, 4729, 4726, 4738:**

This is the richest channel in the dataset. The account management sequence is fully
captured:

**EID 4688 — child `powershell.exe` creation:**
```
Process Command Line: "powershell.exe" & {New...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Token Elevation Type: TokenElevationTypeDefault (1)
Mandatory Label: S-1-16-16384
```
The command line prefix `{New...` is consistent with `New-LocalUser -Name "Administrator "
-NoPassword`.

**EID 4720 — account created:**
```
Account Name: Administrator
Account Domain: ACME-WS06
Security ID: S-1-5-21-1024873681-3998968759-1653567624-1003
SAM Account Name: Administrator
```
The trailing space is preserved verbatim in both the `Account Name` and `SAM Account Name`
fields. The newly assigned SID (1003) confirms this is a distinct account from the built-in
`Administrator` (SID suffix 500).

**EID 4738 — account changed:**
```
Target Account Name: Administrator
SAM Account Name: Administrator
```
This fires immediately after creation as the `New-LocalUser` cmdlet sets account attributes.

**EID 4722 — account enabled:**
```
Target Account Name: Administrator
```
The account is enabled as part of creation.

**EID 4728 — member added to security-enabled global group:**
```
Member SID: S-1-5-21-1024873681-3998968759-1653567624-1003
Group SID: S-1-5-21-1024873681-3998968759-1653567624-513
```
The new account is added to the default `None` group (Domain Users equivalent for local
accounts).

**EID 4729 — member removed from security-enabled global group:**
The same member is removed from the group during cleanup, confirming the ART test ran its
cleanup phase successfully.

**EID 4726 — account deleted:**
The account deletion fires during the cleanup phase (ART restores the system state after
each test). The full creation-modification-deletion lifecycle is captured in a single dataset.

**EID 4703** — token right adjustment enabling elevated privileges for the `powershell.exe`
process, including `SeAssignPrimaryTokenPrivilege`, `SeSecurityPrivilege`,
`SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`.

**EID 4688/4689** — additional process creation/exit events for `whoami.exe` (ART pre- and
post-execution identity checks) and a `"powershell.exe" & {Remo...` child process (the
cleanup script removing the account).

**PowerShell channel (113 events) — EIDs 4104, 4103:**

The 108 EID 4104 events are ART test framework boilerplate. EID 4103 (module logging) records
`Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`, confirming full test completion.

**Application channel (1 event) — EID 15:**

`Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON.` — Defender
re-enabled post-test.

## What This Dataset Does Not Contain

**No Sysmon events.** The Sysmon channel is absent from this undefended dataset collection.
The defended variant contained extensive Sysmon telemetry (EIDs 1, 7, 10, 17) providing
process create details with full command lines, DLL loads, and named pipe creation. None of
that is present here; the Security channel's EID 4688 provides the process creation record
but without the additional context Sysmon would add (hashes, parent image path, etc.).

**No EID 4104 with the `New-LocalUser` command.** The actual user creation command runs
inside a child `powershell.exe` process invoked by the outer ART test framework. The `& {New...`
prefix visible in EID 4688 is the only log-level confirmation of the specific command; the
4104 script block log for the child process would contain the full `New-LocalUser -Name
"Administrator " -NoPassword` text, but this is not present in the 20 sampled events from
the 113-event PowerShell channel.

**No logon events for the new account.** The test creates the account and deletes it without
ever logging into it. No EID 4624 for the `Administrator ` account appears.

## Assessment

The Security channel account management events in this dataset tell the complete attack
story without Sysmon. EID 4720 directly captures the account name `Administrator ` with
the trailing space preserved — this is the most actionable indicator in the dataset. The
SID suffix (1003, not 500) immediately distinguishes it from the built-in administrator,
but a quick visual scan of the `Account Name` field would fool most analysts.

Compared to the defended dataset, the critical difference is the presence of EIDs 4720,
4722, 4726, 4728, 4729, and 4738 — none of which appeared in the defended version due to
account management auditing being disabled. This difference demonstrates how the same
technique produces radically different telemetry depending on audit policy configuration.

The full creation-and-deletion lifecycle in a single 3-second window (all process exits
are `0x0`) is typical of ART test execution and distinguishes this from an adversary who
would create the account and leave it active.

## Detection Opportunities Present in This Data

**Security EID 4720 — account name with trailing space:** Any new local account with a
name matching the pattern `^Administrator\s+$` (or more broadly, any account name that
after trimming matches a high-value account) is a strong indicator. The trailing space is
preserved in the `SAM Account Name` field of EID 4720.

**Security EID 4688 — `New-LocalUser` via child PowerShell:** The command line fragment
`"powershell.exe" & {New...` spawned by a parent `powershell.exe` running as SYSTEM is
anomalous. Local user creation via `New-LocalUser` cmdlet rather than `net user` is less
common in legitimate administrative scripts and should draw scrutiny.

**SID suffix pattern:** EID 4720 assigns SID `...1003` to an account named `Administrator `.
Legitimate environments typically do not create new accounts with names that shadow built-in
accounts. A rule correlating EID 4720 where the account name resembles (but is not equal to)
a built-in account name would catch this.

**EID 4728 followed by EID 4729 within seconds for a new SID:** The same newly created SID
being added and removed from a group within the same session is consistent with automated
test execution. In an adversarial scenario without cleanup, the 4729 would be absent.
