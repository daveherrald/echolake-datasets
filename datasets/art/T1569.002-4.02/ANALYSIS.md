# T1569.002-4: Service Execution — BlackCat Pre-Encryption Commands with Lateral Movement

## Technique Context

MITRE ATT&CK T1569.002 (Service Execution) covers adversary use of the Windows Service
Control Manager to execute programs. This test replicates the pre-encryption command
sequence documented in BlackCat (ALPHV) ransomware investigations. Before encrypting files,
BlackCat operators execute a series of preparatory commands that maximize encryption scope
and enable lateral movement:

1. `wmic csproduct get UUID` — query the system UUID for target fingerprinting
2. `fsutil behavior set SymlinkEvaluation R2L:1` — enable remote-to-local symlink following,
   allowing encryption to traverse symlinks pointing to remote shares
3. `fsutil behavior set SymlinkEvaluation R2R:1` — enable remote-to-remote symlink following
4. `reg add HKLM\...\LanmanServer\Parameters /v MaxMpxCt /d 65535` — increase the SMB
   maximum multiplexed connection limit to enable mass parallel lateral movement
5. Copy PsExec to `%TEMP%` and run it to test access-token enumeration

This test does not perform encryption — it exercises only the preparation and lateral
movement staging phase. The irregular whitespace in command arguments (`wmic \tcsproduct`)
is characteristic of the real BlackCat samples, likely designed to evade simple string-match
detection rules.

In the defended variant, the full command sequence was visible in Sysmon EID 1 process
creates, including the `wmic`, `fsutil`, and `reg` commands. The defended dataset had 60
Sysmon events, 27 Security events, and 45 PowerShell events.

## What This Dataset Contains

With Defender disabled, the preparation sequence executes completely. The dataset spans
approximately 3 seconds (17:41:46–17:41:49 UTC) and contains 167 total events across two
channels.

**Security channel (39 events) — EIDs 4688, 4689, 4703:**

This is the richest process execution record in the dataset. Security EID 4688 captures the
full child process chain:

**WMIC system UUID query:**
```
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "C:\Windows\system32\cmd.exe" /c "wmic 	csproduct 	get UUID"
```
Note the tab characters between `wmic`, `csproduct`, and `get` — this is the BlackCat
whitespace obfuscation preserved verbatim in the log.

```
New Process Name: C:\Windows\System32\wbem\WMIC.exe
Process Command Line: wmic  	csproduct 	get UUID
Creator Process Name: C:\Windows\System32\cmd.exe
Exit Status: 0x0
```
`WMIC.exe` runs successfully and returns the system UUID.

**Symlink evaluation (R2L):**
```
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "C:\Windows\system32\cmd.exe" /c "fsutil behavior 	se...
```
(continuing: `t SymlinkEvaluation R2L:1`)

```
New Process Name: C:\Windows\System32\fsutil.exe
Process Command Line: fsutil  behavior 	set SymlinkEvaluation R2L:1
Exit Status: 0x0
```

**Symlink evaluation (R2R):**
```
New Process Name: C:\Windows\System32\fsutil.exe
Process Command Line: fsutil  behavior set 	SymlinkEvaluation R2R:1
Exit Status: 0x0
```

**Symlink cleanup (R2R restore):**
```
New Process Name: C:\Windows\System32\fsutil.exe
Process Command Line: fsutil  behavior set SymlinkEvaluation R2R:0
Exit Status: 0x0
```
(The ART cleanup phase restoring the default symlink evaluation setting.)

**PowerShell child with BlackCat command block:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {cmd...
```
The `{cmd` prefix indicates the inner script block begins with `cmd.exe /c "wmic..."`,
matching the full BlackCat sequence described above.

**EID 4703** — SYSTEM token rights adjustment enabling the full elevated privilege set,
including `SeAssignPrimaryTokenPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`.
Two separate EID 4703 events fire: one for `powershell.exe` and one for `WMIC.exe`,
confirming WMIC required separate privilege escalation to query system information.

The `cmd.exe` that wraps the initial BlackCat block exits with `0x1`, indicating that
one step in the sequence failed (likely the PsExec lateral movement attempt, which requires
SMB connectivity to `\\$ENV:COMPUTERNAME`). All `fsutil.exe` and `WMIC.exe` processes exit
`0x0`.

**PowerShell channel (128 events) — EIDs 4104, 4103:**

The 124 EID 4104 events are ART test framework boilerplate. EID 4103 records `Set-ExecutionPolicy
Bypass` and `Write-Host "DONE"`. The BlackCat command sequence runs via `cmd.exe` and does
not produce dedicated 4104 script block records beyond the outer test framework wrapper.

## What This Dataset Does Not Contain

**No Sysmon events.** The Sysmon channel is absent. The defended variant's 60 Sysmon events
included EID 1 (process creates with full command lines and hashes), EID 13 (registry value
set for `MaxMpxCt`), EID 10 (process access), EID 17 (named pipe), and EID 7 (DLL loads).
The LanmanServer `MaxMpxCt` registry change is not visible in this dataset because Sysmon
EID 13 is absent.

**No System log events.** The reg.exe operation and any service-related activity are not
captured because the System channel is not collected in this dataset.

**No PsExec execution evidence.** The PsExec lateral movement step (copy PsExec to `%TEMP%`
and run against `\\$ENV:COMPUTERNAME`) likely failed — the `cmd.exe` exit `0x1` indicates
a failure in the sequence. No `PsExec.exe` or `PSEXESVC` process or pipe appears.

## Assessment

The Security channel's EID 4688 records for this dataset provide an excellent process
execution record for the BlackCat preparation sequence. The full command lines for `wmic`,
`fsutil`, and their `cmd.exe` wrappers are visible, with the BlackCat-characteristic
irregular whitespace preserved. The undefended dataset's 39 Security events exceed the
defended dataset's 27, reflecting that without Defender blocking or interfering with process
launches, more of the preparation chain executed and produced events.

The WMIC system UUID query (`wmic csproduct get UUID`) completing successfully with a
`0x0` exit from both the `cmd.exe` wrapper and `WMIC.exe` itself is the clearest indicator
of the preparation phase completing. The two `fsutil.exe` calls enabling symlink evaluation
(`R2L:1`, `R2R:1`) are high-fidelity BlackCat indicators with documented threat intelligence
association.

## Detection Opportunities Present in This Data

**Security EID 4688 — `wmic csproduct get UUID`:** This specific WMIC query for the system
UUID has been documented in BlackCat, Ryuk, and other ransomware families as part of
target fingerprinting. A `WMIC.exe` process with this command line running under SYSTEM is
a high-confidence ransomware precursor indicator.

**Security EID 4688 — `fsutil behavior set SymlinkEvaluation`:** Both `R2L:1` and `R2R:1`
symlink evaluation changes have been specifically documented in BlackCat incident reports.
The presence of both values in rapid succession from a SYSTEM process is a ransomware
behavioral indicator independent of any specific binary hash.

**Security EID 4688 — tab-separated command arguments:** The irregular whitespace in
`wmic  \tcsproduct \tget UUID` and `fsutil  behavior \tset SymlinkEvaluation R2L:1` is a
signature of BlackCat's evasion approach against string-match rules. Detection rules should
normalize whitespace before matching on these command patterns.

**EID 4703 — WMIC privilege elevation:** The separate EID 4703 for `WMIC.exe` requesting
`SeAssignPrimaryTokenPrivilege` and related elevated privileges is an unusual pattern for
normal WMI queries and correlates with the BlackCat reconnaissance phase.
