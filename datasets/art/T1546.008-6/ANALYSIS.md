# T1546.008-6: Accessibility Features — Replace utilman.exe (Ease of Access Binary) with cmd.exe

## Technique Context

T1546.008 (Accessibility Features) is most widely known for the `utilman.exe` replacement variant, which has been used in the wild by multiple threat actors including APT29 and various ransomware operators. `utilman.exe` (Utility Manager / Ease of Access) launches via the Windows logon screen when a user presses Win+U before authenticating. Replacing it with `cmd.exe` or another payload results in a SYSTEM-level shell on the lock screen — a full privilege escalation that requires no credentials. This technique predates modern Windows mitigations and is well-documented in incident reports dating back over a decade. Detection focuses on permission changes and file writes targeting `C:\Windows\System32\utilman.exe`, particularly the use of `takeown.exe` and `icacls.exe` as precursors.

## What This Dataset Contains

The test replaces `utilman.exe` with a copy of `cmd.exe`. Sysmon EID 1 captures the full attack chain command in a single `cmd.exe` invocation (PID 6088, parent `powershell.exe`):

```
"cmd.exe" /c IF NOT EXIST C:\Windows\System32\utilman_backup.exe (copy C:\Windows\System32\utilman.exe C:\Windows\System32\utilman_backup.exe) ELSE ( pushd ) & takeown /F C:\Windows\System32\utilman.exe /A & icacls C:\Windows\System32\utilman.exe /grant Administrators:F /t & copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

Sysmon EID 1 records three additional named process creates: `whoami.exe` (SYSTEM context check), `takeown.exe` (`CommandLine: takeown /F C:\Windows\System32\utilman.exe /A`, tagged `T1222.001`), and `icacls.exe` (`CommandLine: icacls C:\Windows\System32\utilman.exe /grant Administrators:F /t`, tagged `T1222.001`).

Sysmon EID 11 (FileCreate) captures the most critical artifact: `C:\Windows\System32\Utilman.exe` written by `cmd.exe` as NT AUTHORITY\SYSTEM. This is the direct overwrite record:

```
Image: C:\Windows\system32\cmd.exe
TargetFilename: C:\Windows\System32\Utilman.exe
CreationUtcTime: 2026-03-13 02:04:52.174
```

Note the `CreationUtcTime` reflects the original `cmd.exe` binary's timestamp being applied to the new file — a file copy preserves the source's timestamp, which is itself a useful forensic artifact.

Security EID 4688 records four process creations (including `takeown.exe` and `icacls.exe`) and EID 4689 provides nine termination events. Two EID 4703 (token right adjustment) events appear for SYSTEM.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

Because object access auditing is disabled, there are no Security EID 4663 (file access) or EID 4660 (file delete) events recording the deletion of the original `utilman.exe` before the copy. The backup file creation (`utilman_backup.exe`) does not appear as a separate Sysmon EID 11 in this dataset — only the final overwrite of `Utilman.exe` is captured. There is no Sysmon EID 11 for `utilman_backup.exe` likely because the backup already existed (the `ELSE pushd` branch ran), though the exact execution path is inferrable from the EID 1 command line.

## Assessment

This dataset is strong for detection engineering on the utilman binary replacement pattern. The three-event combination — `takeown` + `icacls` + `cmd.exe` overwrite of an accessibility binary (all in EID 1), followed by the EID 11 FileCreate for `Utilman.exe` written by `cmd.exe` — is highly specific and forms a tight behavioral cluster. The timestamp discrepancy on the EID 11 event (original `cmd.exe` creation time applied to the replaced `Utilman.exe`) is an additional forensic signal. Enabling Security object access auditing on System32 files would add EID 4663/4660 coverage.

## Detection Opportunities Present in This Data

1. **Sysmon EID 11 — FileCreate for `C:\Windows\System32\Utilman.exe` (or any accessibility binary) written by `cmd.exe` as SYSTEM** — direct overwrite of a protected system binary.
2. **Sysmon EID 1 — `takeown.exe` with `/F C:\Windows\System32\utilman.exe`** as SYSTEM; indicator of pre-tamper permission acquisition, tagged `T1222.001`.
3. **Sysmon EID 1 — `icacls.exe` granting `Administrators:F` on an accessibility binary** in `C:\Windows\System32\`, tagged `T1222.001`.
4. **Sysmon EID 1 — `cmd.exe` command line containing `copy ... cmd.exe ... utilman.exe`** (or any copy of a shell to an accessibility tool path) — payload placement.
5. **Security EID 4688 — `takeown.exe` and `icacls.exe` process creations as SYSTEM targeting System32** within the same logon session in rapid succession.
6. **Sysmon EID 11 — timestamp mismatch: FileCreate TargetFilename points to an accessibility binary but `CreationUtcTime` matches a different known-good binary's timestamp** — file copy forensic artifact.
