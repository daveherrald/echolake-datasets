# T1490-6: Inhibit System Recovery — Delete Backup Files

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes direct deletion of backup file artifacts as a complementary step to shadow copy deletion. This test uses `del /s /f /q` to target common backup file extensions across the C: drive: `.VHD`, `.bac`, `.bak`, `.wbcat`, `.bkf`, `.set`, `.win`, `.dsk`, and files matching `Backup*.*`. Ransomware operators use this pattern to eliminate backup files that may have been placed on the local disk before an encryption pass — particularly relevant when target organizations store backups locally rather than air-gapped. Families including Emotet-distributed ransomware and older variants use wildcard file deletion before or after encryption.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The full command is captured: `"cmd.exe" /c del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk`. This runs as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. Sysmon tags the `cmd.exe` invocation with `technique_id=T1059.003`. Notably, the `del` command is a `cmd.exe` built-in — no separate child process is spawned for the deletion itself. `del` does not produce a process create event.

**Security (Event IDs 4688/4689/4703):**
`cmd.exe` creation and exit are recorded. Because `del` is internal to `cmd.exe`, only two process events appear (create and exit for `cmd.exe`). The process exits with `0x0`. No backup files existed on this test VM, so deletion succeeded vacuously. Token right adjustment (4703) is present for the `cmd.exe` process.

**Application log (Event ID 16384):**
`"Successfully scheduled Software Protection service for re-start at 2026-05-03T04:06:03Z. Reason: RulesEngine."` — this is a spurious side effect from the Software Protection Platform responding to the extended execution window, not related to the backup deletion technique.

**Task Scheduler (Event ID 140):**
`User "ACME\ACME-WS02$" updated Task Scheduler task "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"` — again a background artifact from Software Protection Platform activity, not technique-related.

**PowerShell channel:** Contains only `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` test framework boilerplate. The `del` command is executed by `cmd.exe` directly, so no PowerShell technique content is present.

## What This Dataset Does Not Contain

- **No Sysmon EID 23 (FileDelete)** or EID 11 (FileCreate with deletion marker). Sysmon's file deletion telemetry would require explicit configuration of the `FileDelete` event type (EID 23), which is not present in the sysmon-modular configuration used here. The actual file deletions are not logged.
- **No indication of which files (if any) were deleted.** On this test VM there were no `.VHD`, `.bak`, `.bkf`, or other targeted backup files on the C: drive, so no real data was destroyed. The successful `cmd.exe` exit only confirms the `del` command ran without errors — it does not confirm files were found.
- **No Security object access events.** Object access auditing is set to `none` in this environment's audit policy, so no EID 4663 (file deletion) events are generated.
- **No Sysmon EID 3 network events** related to the technique — the backup file deletion does not reach out to the network.

## Assessment

This dataset captures the attempt telemetry cleanly — the full `del` command with all targeted extensions is visible in both Sysmon EID 1 and Security EID 4688. However, because `del` is a `cmd.exe` built-in and file deletion auditing is not enabled, there is no visibility into what files were actually touched. For detection engineering, the command-line pattern (multiple backup extensions in a single `del /s /f /q` invocation) is the primary detection surface. The Task Scheduler and Application log artifacts are incidental noise that should be filtered in production rules. Adding Sysmon EID 23 (FileDelete) configuration would substantially improve this dataset.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `cmd.exe /c del /s /f /q` targeting multiple backup extensions** (`.VHD`, `.bak`, `.bkf`, `.wbcat`, `Backup*.*`) in a single command — the multi-extension wildcard pattern is a high-confidence ransomware indicator.
2. **Security EID 4688 — `cmd.exe` command line containing backup extension wildcards** — independent of Sysmon, the full argument string is captured via command-line auditing.
3. **Extension list as an indicator set** — the specific combination of `.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf` is a fingerprint observable across multiple ransomware families and is low-likelihood in legitimate administrative use.
4. **SYSTEM context + TEMP directory** — `del` targeting C: drive backup files launched by SYSTEM from `C:\Windows\TEMP\` has no legitimate administrative justification.
5. **Temporal correlation with other T1490 actions** — in a real ransomware scenario this command typically co-occurs with VSC deletion and bcdedit operations within seconds; sequential detection across these T1490 sub-techniques is a stronger signal than any single event.
