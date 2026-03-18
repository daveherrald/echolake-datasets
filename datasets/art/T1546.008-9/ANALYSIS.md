# T1546.008-9: Accessibility Features — Replace DisplaySwitch.exe (Display Switcher Binary) with cmd.exe

## Technique Context

T1546.008 (Accessibility Features) covers abuse of Windows accessibility and system utility binaries that run before authentication at the lock screen. `DisplaySwitch.exe` is the Display Switch utility that handles display projection modes. While less commonly exploited than `utilman.exe` or `osk.exe`, it is accessible from the logon screen and can be invoked before authentication. Replacing it with a command shell produces a SYSTEM-level process with no credential requirement. This test follows the same takeown-icacls-copy pattern as tests 6, 7, and 8, completing the coverage of the four main replacement targets across this test series.

## What This Dataset Contains

Sysmon EID 1 records four process creates: `whoami.exe` (SYSTEM context check), `cmd.exe` with the full replacement command targeting `C:\Windows\System32\DisplaySwitch.exe`, `takeown.exe` (`/F C:\Windows\System32\DisplaySwitch.exe /A`, tagged `T1222.001`), and `icacls.exe` (granting `Administrators:F`, tagged `T1222.001`).

Sysmon EID 11 captures the file overwrite:

```
Image: C:\Windows\system32\cmd.exe
TargetFilename: C:\Windows\System32\DisplaySwitch.exe
CreationUtcTime: 2026-03-10 12:15:45.556
```

The `CreationUtcTime` is March 10, 2026 — three days before the test execution (March 13, 23:42) — confirming the file copy carries the source binary's original timestamp.

Security EID 4688 records four process creations as SYSTEM. EID 4689 records ten process terminations (including a `svchost.exe` process that exited during the window, unrelated to the test). Two EID 4703 (token right adjustment) events appear. Notably this dataset does not have the Security EID 4624/4672 logon events seen in test 7 — no new WMI session was created, as this test runs via direct PowerShell execution.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

As with tests 6 and 8, object access auditing is disabled (no EID 4663/4660). The backup file creation (`DisplaySwitch_backup.exe` or equivalent) is not captured in EID 11 — consistent with prior tests where the conditional backup step was skipped. No WMI delivery vector is present (unlike test 7).

## Assessment

This dataset rounds out the binary replacement coverage for the T1546.008-6 through -9 series. Taken together, these four datasets demonstrate that a single detection rule matching `FileCreate` on the set of accessibility binary names in `C:\Windows\System32\` combined with a `cmd.exe` writing process — or alternatively the `takeown` + `icacls` + file write triple on any System32 accessibility path — will fire on all four variants without modification. The timestamp mismatch pattern (EID 11 `CreationUtcTime` predating execution by days) appears consistently across all four tests and is a reliable heuristic for file-copy-based replacement.

## Detection Opportunities Present in This Data

1. **Sysmon EID 11 — FileCreate for `C:\Windows\System32\DisplaySwitch.exe` written by `cmd.exe` as SYSTEM** — direct binary overwrite.
2. **Sysmon EID 1 — `takeown.exe /F C:\Windows\System32\DisplaySwitch.exe`** followed within milliseconds by `icacls.exe` granting `Administrators:F` on the same path.
3. **Sysmon EID 11 — `CreationUtcTime` on the accessibility binary is days before execution time** — copy-from-another-binary forensic signal.
4. **Security EID 4688 — SYSTEM executing `takeown.exe` and `icacls.exe` targeting `C:\Windows\System32\` paths** — permission modification before file tamper.
5. **Generic rule across tests 6–9: Sysmon EID 11 FileCreate targeting any of {utilman.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe, osk.exe} by a process other than a Windows installer or updater** — covers the full accessibility binary replacement attack surface.
