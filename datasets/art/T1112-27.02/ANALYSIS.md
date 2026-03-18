# T1112-27: Modify Registry — Hide Windows Clock Group Policy Feature

## Technique Context

The `HideClock` Group Policy value (`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` set to `1`) removes the clock and time display from the Windows taskbar notification area. While removing the clock is a subtle modification compared to disabling Control Panel or the Run dialog, it serves a tactical purpose: an attacker who has restricted access to time-keeping UI elements makes it marginally harder for a victim to correlate events to timestamps or notice time-based anomalies such as unusual late-night activity.

More practically, this test represents one modification in a sustained series of Explorer policy key changes targeting the same registry path across multiple successive tests. In a real attack scenario, an operator performing multiple UI-restriction modifications in sequence would generate a cluster of similar `reg add` events within a short window — a pattern that is more detectable as a group than any single modification.

This dataset is distinctive within the T1112 series for three reasons: it contains the fewest PowerShell events (36 EID 4104), it includes a Sysmon EID 13 (RegistryEvent SetValue) capturing a legitimate but adjacent registry write, and it includes a Security EID 4702 (scheduled task updated) alongside Task Scheduler activity — providing richer ambient context than most other tests in this series.

## What This Dataset Contains

This dataset captures 63 events across five channels (1 Application, 36 PowerShell, 5 Security, 20 Sysmon, 1 Task Scheduler) collected over a 5-second window (2026-03-14T23:49:44Z–23:49:49Z) on ACME-WS06 with Defender disabled.

**Application Channel (EID 16384):**
One Application EID 16384 event: `Successfully scheduled Software Protection service for re-start at 2026-05-03T04:05:44Z. Reason: RulesEngine.` This is the Windows Software Licensing / KMS client scheduling its next activation check. It is background OS activity, not related to the T1112 test.

**Process Creation Chain (Security EID 4688):**

Four EID 4688 events:
1. `whoami.exe` — pre-test identity check
2. `cmd.exe` with command: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideClock /t REG_DWORD /d 1 /f`
3. `reg.exe` with command: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideClock /t REG_DWORD /d 1 /f`
4. `whoami.exe` — post-test identity check

**Security EID 4702 — Scheduled Task Updated:**

One EID 4702 event records a scheduled task update under account `ACME\ACME-WS06$` (the computer account, not a user) for task `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`. This is the Software Protection Platform scheduling itself — a Windows licensing maintenance task. The event includes the full XML task definition, which is a useful forensic artifact when legitimate vs. malicious scheduled tasks need to be distinguished.

**Task Scheduler Channel (EID 140):**

One EID 140 event: `User "ACME\ACME-WS06$" updated Task Scheduler task "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"`. This confirms the same SPP task update, now from the Task Scheduler operational log perspective.

**Sysmon Registry Value Set (EID 13):**

One EID 13 event captures a registry write by `svchost.exe` (PID 1500) to:
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index
```
with `Details: DWORD (0x00000003)`. This is the Task Scheduler service writing the SPP task index entry — the underlying registry operation that corresponds to the EID 4702 scheduled task update. The Sysmon rule tag is `technique_id=T1053,technique_name=Scheduled Task`, which is accurate: task cache writes in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` are associated with scheduled task creation and modification.

**Sysmon Network Connection (EID 3):**

One EID 3 event records an outbound TCP connection from `svchost.exe` (the network location proxy service) — this is part of the Software Protection Platform's KMS or activation check, consistent with the EID 16384 Application event and the scheduled task update.

**Sysmon Process Creates (EID 1):**

Four EID 1 events: `whoami.exe` (pre-test), `cmd.exe` with HideClock command (SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`), `reg.exe` (SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`), `whoami.exe` (post-test). All consistent with the other T1112 tests.

**PowerShell Script Block Logging (EID 4104):**

36 EID 4104 events — significantly fewer than T1112-19 (93) and T1112-22 (93). This variation reflects timing: fewer PowerShell internal fragments were compiled within this collection window. Substantive script blocks — `$startEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` and `$endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` — appear among the 4104 events, which are the ART test framework timing stamps around the test execution. These are consistent markers in the ART test framework and are not attack-related.

## What This Dataset Does Not Contain

- **Sysmon EID 13 for the HideClock registry write:** The SPP task cache write is captured in EID 13, but the `HideClock` write itself is not — the Sysmon configuration does not monitor `HKCU\...\Policies\Explorer` for SetValue events.
- **The HideClock effect on the taskbar:** No event captures the clock disappearing from the notification area.
- **The contents of the SvcRestartTask XML beyond the EID 4702 event:** The full task XML is embedded in the 4702 message field but is not individually queryable without parsing the Security event.

## Assessment

T1112-27 is the richest ambient-context dataset in the T1112 series. The Software Protection Platform (SPP) activity — Application EID 16384, Security EID 4702, Task Scheduler EID 140, and Sysmon EID 13 for the task cache write — all fire within the same collection window as the HideClock registry modification, providing a realistic example of how legitimate OS maintenance activity overlaps with attack telemetry in time.

The Sysmon EID 13 event is particularly valuable because it demonstrates what an actual registry value set event looks like in this environment: it targets `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\...` and is written by `svchost.exe`. An EID 13 targeting `HKCU\...\Policies\Explorer` written by `reg.exe` would look structurally similar but would be immediately suspicious — confirming that EID 13 monitoring for the Explorer policy path would be a precise detection for this family.

Compared to the defended variant (73 events: 34 PowerShell, 12 Security, 27 Sysmon), this undefended dataset (63 events) is slightly smaller, primarily due to the lower PowerShell count (36 vs. 34 — the difference is negligible, and the ambient background events are different between the two runs).

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — HideClock in reg add Command:**
The `reg add` command targeting `HKCU\...\Policies\Explorer` with value `HideClock` is the direct attack indicator. The family-level pattern covering any value under this path remains the most durable detection.

**Sysmon EID 13 — Registry SetValue Monitoring Opportunity:**
The SPP task cache write shows what EID 13 looks like in this environment. Adding the `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` path to the Sysmon registry monitoring configuration would capture the HideClock write (and all other Explorer policy modifications in this series) as direct EID 13 events, eliminating reliance on process creation chain inference.

**Security EID 4702 — Scheduled Task Update Baseline:**
The `SvcRestartTask` update by `ACME\ACME-WS06$` (computer account) using the SPP path is a baseline example of legitimate scheduled task modification. EID 4702 events from user accounts (rather than computer accounts) or from unexpected task paths would warrant investigation.

**Task Scheduler EID 140 — Legitimate Task Update Baseline:**
Task Scheduler EID 140 (`\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`) correlates with Security EID 4702 for the same event, providing cross-channel confirmation of legitimate scheduled task activity.
