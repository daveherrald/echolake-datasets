# T1562.002-4: Disable Windows Event Logging — Impair Windows Audit Log Policy

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses `auditpol.exe` to disable multiple audit policy subcategories across several categories — Account Logon, Logon/Logoff, and Detailed Tracking — using a single chained `cmd.exe` command. Disabling audit policy prevents Security event log entries from being generated for covered activity: logons stop being recorded, process creation events stop being generated, and privilege use events disappear. Unlike disabling the Event Log service (which is obvious), audit policy changes are quiet — Windows silently stops generating those event types, and most monitoring systems will not alert on silence.

The practical impact is that after this technique runs, `auditpol /get /category:*` would show "No Auditing" for these subcategories, and activity that would normally generate Security events in those categories will go unrecorded until audit policy is restored.

## What This Dataset Contains

The dataset spans roughly four seconds and captures 149 events across PowerShell (107), Security (41), and Application (1) channels.

**Security (EID 4688):** Six process creation events. PowerShell (parent) spawns `whoami.exe` (test framework identity check), then spawns `cmd.exe` with the attack command:

```
"cmd.exe" /c auditpol /set /category:"Account Logon" /success:disable /failure:disable & auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable & auditpol /set /category:"Detailed Tracking" /success:disable
```

`cmd.exe` then spawns three separate `auditpol.exe` processes in sequence:

```
auditpol  /set /category:"Account Logon" /success:disable /failure:disable
auditpol  /set /category:"Logon/Logoff" /success:disable /failure:disable
auditpol  /set /category:"Detailed Tracking" /success:disable
```

All processes run as `NT AUTHORITY\SYSTEM` (S-1-5-18) with System integrity label and `TokenElevationTypeDefault (1)`.

**Security (EID 4719):** 28 audit policy change events — the most forensically valuable portion of the dataset. EID 4719 fires once per subcategory disabled, before those changes take effect (the audit subsystem records the change in the last moment it can). Subcategories captured include:

- Logon/Logoff: `Logon` — "Success removed, Failure removed" (GUID `{0cce9215-69ae-11d9-bed3-505054503030}`)
- Logon/Logoff: `Special Logon` — "Success removed"
- Logon/Logoff: `Network Policy Server` — "Success removed, Failure removed"
- Logon/Logoff: `Account Lockout` — "Success removed"
- Logon/Logoff: `Logoff` — "Success removed"
- Detailed Tracking: `Process Creation` — "Success removed" (GUID `{0cce922b-69ae-11d9-bed3-505054503030}`)
- Account Logon: `Kerberos Authentication Service` — "Success Added, Failure added" (appears as a restore event during cleanup)
- Account Logon: `Kerberos Service Ticket Operations` — "Success Added, Failure added"
- Account Logon: `Credential Validation` — "Success Added, Failure added"
- Account Logon: `Other Account Logon Events` — "Success Added, Failure added"

The "Success Added, Failure added" events are from the cleanup phase — the ART test framework restores audit policy after the test, generating EID 4719 events with the opposite direction.

**Security (EID 4689):** Six process exit events for the processes above.

**Security (EID 4703):** One token right adjustment event for `powershell.exe`.

**Application (EID 15):** One event: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." This is a Windows Security Center status update, a background event unrelated to the technique.

**PowerShell (EID 4103 + 4104):** 107 events. Three EID 4103 events record `Set-ExecutionPolicy Bypass` and related test framework cmdlets. The `Invoke-AtomicTest` cleanup block is absent from the 4104 samples — this test's cleanup was also via `auditpol.exe` (restoring policy), not via a distinct Invoke-AtomicTest cleanup call visible in this sample set.

## What This Dataset Does Not Contain

**No Sysmon events.** The defended variant captured 20 Sysmon events including EID 1 (process creates with parent-chain annotations for `cmd.exe` and `auditpol.exe`), EID 10 (process access), EID 11 (file creates), and EID 17 (named pipe). None is present here.

**No Security EID 4688 for individual `auditpol.exe` subprocesses in some views.** The dataset does contain 4688 for the three `auditpol.exe` invocations — this is richer than the defended variant, which also had `auditpol.exe` in 4688. Both datasets fully capture the command lines.

**No evidence of post-attack silence.** The most dangerous effect of this technique — that audit events stop being generated — cannot itself be recorded. There is no event that says "audit policy is now disabled, events will no longer be generated." The 4719 events are the last record before the silence begins.

**Cleanup events mixed in.** The EID 4719 events showing "Success Added, Failure added" are from the cleanup phase, not the attack. Both attack and cleanup 4719 events are present in this dataset and must be interpreted together.

## Assessment

The technique executed successfully. The 28 EID 4719 events form a comprehensive, subcategory-level record of every audit policy change — both the attack phase (disabling) and the cleanup phase (restoring). This dataset is unusually rich in direct technique telemetry because EID 4719 is purpose-built to record audit policy changes, fires once per subcategory, and cannot be suppressed by the technique itself (the change is recorded before taking effect).

Compared to the defended variant (20 Sysmon + 36 Security + 35 PowerShell + 2 Application + 1 TaskScheduler = 94 total), the undefended run produced 107 PowerShell + 41 Security + 1 Application events (149 total). The higher Security count in the undefended run reflects the fuller set of EID 4719 and 4689 events captured — the 41 vs. 36 difference is accounted for by additional process exit events and cleanup-phase 4719 records.

## Detection Opportunities Present in This Data

- **Security EID 4719:** Any instance of `Changes: Success removed` or `Failure removed` on subcategories in Logon/Logoff, Detailed Tracking, or Account Logon categories is a direct indicator of audit policy impairment. The subcategory GUIDs (e.g., `{0cce9215-69ae-11d9-bed3-505054503030}` for Logon) provide reliable matching even if the subcategory display name varies.
- **Security EID 4688 (cmd.exe):** Command line containing `auditpol /set /category:` with `/success:disable` or `/failure:disable` — any such invocation is worth alerting on regardless of the specific category targeted.
- **Security EID 4688 (auditpol.exe):** `auditpol.exe` processes spawned by `cmd.exe` which itself was spawned by `powershell.exe` under SYSTEM context — this process chain is uncommon in legitimate administration.
- **Baseline deviation:** Monitoring for a sudden drop in EID 4624 (logon), 4688 (process create), or 4634 (logoff) volume after an `auditpol /set` event can confirm that audit policy impairment is actively suppressing telemetry.
