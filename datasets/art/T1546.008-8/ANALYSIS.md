# T1546.008-8: Accessibility Features — Replace Narrator.exe (Narrator Binary) with cmd.exe

## Technique Context

T1546.008 (Accessibility Features) applies to any of the accessibility binaries invokable from the Windows lock screen. `Narrator.exe` (Windows Narrator, a screen reader) can be triggered from the logon UI's Ease of Access menu. Replacing it with a command interpreter gives an attacker SYSTEM-level access at the lock screen without credentials. This test follows the same takeown-icacls-copy pattern as the utilman and Magnify replacements (tests 6 and 7) but targets `Narrator.exe`. From a detection standpoint, the three binary-replacement tests (6, 7, 8) are functionally identical in their telemetry structure — the distinguishing field is the target accessibility binary name.

## What This Dataset Contains

Sysmon EID 1 records four process creates: `whoami.exe` (SYSTEM context check), `cmd.exe` with the full replacement command chain targeting `C:\Windows\System32\Narrator.exe`, `takeown.exe` (`/F C:\Windows\System32\Narrator.exe /A`, tagged `T1222.001`), and `icacls.exe` (granting `Administrators:F` on `Narrator.exe`, tagged `T1222.001`).

The `cmd.exe` command line (EID 1) is:
```
"cmd.exe" /c IF NOT EXIST C:\Windows\System32\Narrator_backup.exe (copy C:\Windows\System32\Narrator.exe C:\Windows\System32\Narrator_backup.exe) ELSE ( pushd ) & takeown /F C:\Windows\System32\Narrator.exe /A & icacls C:\Windows\System32\Narrator.exe /grant Administrators:F /t & copy C:\Windows\System32\cmd.exe C:\Windows\System32\Narrator.exe
```

Sysmon EID 11 records the file overwrite:

```
Image: C:\Windows\system32\cmd.exe
TargetFilename: C:\Windows\System32\Narrator.exe
CreationUtcTime: 2026-03-13 02:04:52.096
```

The `CreationUtcTime` (March 13 02:04) differs from the test execution time (March 13 23:42), confirming this is a file copy that carries the source binary's original timestamp — a forensic marker.

Security EID 4688 records four process creations under SYSTEM. Two EID 4703 (token right adjustment) events appear for the SYSTEM session. EID 4689 records nine process terminations.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

Object access auditing is disabled, so EID 4663 (file object access) and EID 4660 (handle close with delete) events are absent. The backup file (`Narrator_backup.exe`) does not appear in EID 11 — consistent with the prior test, the conditional backup step may have been skipped because the backup already existed from a previous test run in the same session. There are no WMI activity events (compare with test 7 which showed the WMI delivery vector).

## Assessment

This is a clean, well-formed accessibility binary replacement dataset with strong telemetry. The combination of Sysmon EID 1 (full command line with the copy-chain), EID 11 (file overwrite with timestamp discrepancy), and Security EID 4688 (SYSTEM process chain) provides three independent detection anchors. Because tests 6, 7, and 8 follow the same pattern targeting different binaries, they collectively enable writing a generic detection rule matching any accessibility binary path in System32 rather than requiring per-binary detections.

## Detection Opportunities Present in This Data

1. **Sysmon EID 11 — FileCreate for `C:\Windows\System32\Narrator.exe` written by `cmd.exe` as SYSTEM** — direct binary overwrite artifact.
2. **Sysmon EID 1 — `takeown.exe /F C:\Windows\System32\Narrator.exe`** immediately preceding a file write to the same path — pre-tamper ownership acquisition.
3. **Sysmon EID 1 — `icacls.exe` granting `Administrators:F` on an accessibility binary** in System32 — pre-tamper ACL weakening.
4. **Sysmon EID 11 — timestamp discrepancy: `CreationUtcTime` for the accessibility binary path matches a different system binary's compile/copy date** rather than the current time — file copy forensic signal.
5. **Security EID 4688 — `takeown.exe` and `icacls.exe` as SYSTEM modifying `C:\Windows\System32\` paths** within 15ms of each other — tight temporal coupling.
6. **Generic: Sysmon EID 1 `cmd.exe` containing `copy ... cmd.exe ... <accessibility binary name>.exe`** — covers utilman, Magnify, Narrator, DisplaySwitch as a single pattern.
