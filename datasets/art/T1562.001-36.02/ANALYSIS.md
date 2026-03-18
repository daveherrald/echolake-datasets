# T1562.001-36: Disable or Modify Tools — Disable Windows Defender with PwSh Disable-WindowsOptionalFeature

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes removing Windows
Defender entirely as an OS optional feature. The `Disable-WindowsOptionalFeature` PowerShell
cmdlet wraps the Windows DISM API and can attempt to remove Defender components: the GUI
(`Windows-Defender-Gui`), runtime features (`Windows-Defender-Features`), the core service
(`Windows-Defender`), and Application Guard (`Windows-Defender-ApplicationGuard`).

Unlike test 27 (which invokes DISM directly via `cmd.exe`), this test uses the PowerShell
DISM module wrapper and targets four feature names in sequence. Adversaries with
SYSTEM-level access may attempt this to permanently remove Defender rather than just
disabling configuration settings.

In this **undefended** dataset, Defender is disabled at the policy level. This test engages
the full Windows Modules Installer (TrustedInstaller) pipeline, producing one of the richest
telemetry sets in this batch.

## What This Dataset Contains

The dataset captures 163 events across four channels (140 PowerShell, 16 Security, 2 System,
5 Task Scheduler) spanning approximately 8 seconds on ACME-WS06 (Windows 11 Enterprise
Evaluation, 2026-03-17).

**Security EID 4688 — Ten process creation events.** The full chain includes:

1. `"C:\Windows\system32\whoami.exe"` (pre-execution ART identity check)
2. Child `powershell.exe` with the full attack command:
   ```
   "powershell.exe" & {Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Gui" -NoRestart -ErrorAction Ignore
   Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Features" -NoRestart -ErrorAction Ignore
   Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender" -NoRestart -ErrorAction Ignore
   Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -ErrorAction Ignore}
   ```
3. `C:\Windows\System32\Dism\DismHost.exe {F1DDD389-198B-494C-A2C5-3CDF16C687A6}`
4. `C:\Windows\servicing\TrustedInstaller.exe`
5. `C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_...\TiWorker.exe -Embedding`
6. `C:\Windows\System32\Dism\DismHost.exe {232B4C0E-D36D-4766-BCD2-CE5C9DA97A51}`
7. `C:\Windows\System32\Dism\DismHost.exe {3078649D-F4CF-415E-85BC-DD1F19B958AB}`
8. `C:\Windows\System32\Dism\DismHost.exe {8BC08B03-5AD0-4628-8307-C117FF63B142}`
9. `"C:\Windows\system32\sdbinst.exe" -mm`
10. `"C:\Windows\system32\whoami.exe"` (post-execution ART identity check)

The four `DismHost.exe` invocations each carry a unique GUID, corresponding to separate
feature processing requests for each feature name. `TrustedInstaller.exe` and `TiWorker.exe`
are the Windows Modules Installer components that execute the actual feature management
work. `sdbinst.exe -mm` (application compatibility database installer) is spawned by the
DISM pipeline as part of the servicing state update.

**Security EID 4663 — Four file access events** from `TiWorker.exe` accessing files under
`C:\Windows\servicing\Sessions\`:
```
C:\Windows\servicing\Sessions\31241780_3333999873.xml
C:\Windows\servicing\Sessions
```
These are the Windows Component Based Servicing session files written during the feature
removal attempt, providing a record of the DISM servicing session.

**Security EID 4624 and 4672 — Logon events.** One network logon from `services.exe`
(`SubjectUserSid: S-1-5-18`) and one special logon for `SYSTEM` (`SubjectUserName: SYSTEM`,
`NT AUTHORITY`), associated with the TrustedInstaller service starting.

**System EID 7040 — Windows Modules Installer service startup type change:**
```
The start type of the Windows Modules Installer service was changed from demand start to auto start.
The start type of the Windows Modules Installer service was changed from auto start to demand start.
```
TrustedInstaller was temporarily set to auto-start to support the DISM pipeline, then reset
to demand-start. These two System events bracket the servicing activity.

**Task Scheduler events (EIDs 100, 102, 129, 200, 201):** The
`SdbinstMergeDbTask` scheduled task executed `sdbinst.exe` as part of application
compatibility database processing triggered by the DISM pipeline. The task ran
`%windir%\system32\sdbinst.exe` under instance GUID
`{def46343-e97b-43f3-8d94-c853b04a7114}`.

**PowerShell EID 4104 — 113 script block events.** The ART test framework boilerplate is present.
The three 4100 error events (visible in the EID breakdown but not in the sampled 20 events)
capture errors for three of the four unrecognized feature names: `Windows-Defender-Gui`,
`Windows-Defender-Features`, and `Windows-Defender` are not valid feature names on Windows
11 Enterprise Evaluation. `Windows-Defender-ApplicationGuard` did not generate a 4100 error
(it either succeeded partially, was silently skipped via `-ErrorAction Ignore`, or has a
different failure mode).

**PowerShell EID 4103 — 24 module pipeline events**, substantially more than other tests
in this batch, consistent with the more complex DISM/TrustedInstaller execution pipeline
generating pipeline output.

## What This Dataset Does Not Contain

**Sysmon events.** Sysmon is not bundled in the undefended dataset for this test. The
defended variant includes Sysmon EID 1 for `whoami.exe`, the child `powershell.exe`, and
`sdbinst.exe`, along with EID 7 (image loads) and EID 10 (process access).

**Confirmation of successful feature removal.** The three 4100 errors confirm that
`Windows-Defender-Gui`, `Windows-Defender-Features`, and `Windows-Defender` are not
recognized feature names on this Windows 11 Enterprise Evaluation build. Whether the
fourth feature (`Windows-Defender-ApplicationGuard`) was processed successfully is not
confirmed by events in the sampled data. No Security 4657 or Sysmon 13 registry write
confirms Defender components were actually removed.

**DISM.exe as a direct process.** `DismHost.exe` appears (the out-of-process DISM worker),
but a top-level `dism.exe` process does not appear in the 4688 events — the PowerShell
DISM module invokes the DISM API internally rather than spawning `dism.exe` as a subprocess.

**The full set of 4100 error messages.** The sampled 20 PowerShell events do not include
the three 4100 error events (they are present in the total count of 140 but were not
selected in the 20-event sample). The full dataset file (`data/powershell.jsonl`) contains
these events.

## Assessment

This dataset is the richest in the T1562.001 batch for undefended execution because
`Disable-WindowsOptionalFeature` successfully engaged the DISM and TrustedInstaller
pipeline, producing events across four distinct channels. The four `DismHost.exe` processes,
`TrustedInstaller.exe` startup, `TiWorker.exe` servicing work, and the `SdbinstMergeDbTask`
task execution all appear as a direct consequence of the attack command.

Compared to test 27 (DISM via `cmd.exe`), this variant generates substantially more
telemetry because the PowerShell DISM module invokes a more complete servicing pipeline
path. The defended dataset for test 36 is essentially identical in structure — both the
defended and undefended runs engaged the same DISM pipeline with the same feature name
errors — because this technique was not blocked by Tamper Protection (the feature names
were simply invalid).

The System EID 7040 TrustedInstaller startup type changes are particularly useful for
correlation: they bracket the DISM activity temporally and are not common in normal system
operation.

## Detection Opportunities Present in This Data

**Security EID 4688 — `Disable-WindowsOptionalFeature` targeting `Windows-Defender`
feature names.** The PowerShell child process command line contains all four feature names.
The specific string `Windows-Defender` in a `Disable-WindowsOptionalFeature` or
`Disable-Feature` command targeting an online system is a high-confidence indicator.

**Security EID 4688 — `DismHost.exe` spawned with GUID arguments.** Four
`DismHost.exe {GUID}` processes appearing in rapid succession within a narrow time window
is uncommon in normal OS operation and is consistent with a scripted feature removal
attempt.

**Security EID 4688 — `TrustedInstaller.exe` and `TiWorker.exe` spawning in context with
a PowerShell DISM command.** The Windows Modules Installer starting in direct temporal
proximity to a PowerShell `Disable-WindowsOptionalFeature` command targeting Defender is
a meaningful behavioral correlation.

**System EID 7040 — Windows Modules Installer startup type change.** The demand-start to
auto-start transition (and the reversal) for TrustedInstaller is a low-volume, high-signal
event that anchors the DISM activity in the system event log. Correlating 7040 events with
suspicious PowerShell activity in the preceding seconds is a reliable detection strategy.

**Task Scheduler EID 129/200/201 — `SdbinstMergeDbTask` execution.** The
application compatibility database task firing in conjunction with DISM activity is
a secondary indicator that the DISM pipeline processed at least one feature modification
request (even if unsuccessful).
