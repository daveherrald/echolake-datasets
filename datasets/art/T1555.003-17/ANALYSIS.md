# T1555.003-17: Credentials from Web Browsers — Dump Chrome Login Data with esentutl

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes the use of living-off-the-land binaries (LOLBins) to access locked browser credential files. Chrome's `Login Data` SQLite database is locked by the browser process while Chrome is running. Adversaries use `esentutl.exe` — a legitimate Windows database utility — to bypass this lock by performing a volume shadow copy-style database copy (`/y` flag for copy, `/d` for destination) at the VSS or OS level. `esentutl.exe` is a signed Microsoft binary present on all Windows systems, making it highly effective for evading application-control policies.

## What This Dataset Contains

**Commands executed (Security 4688 and Sysmon EID=1):**
```
"cmd.exe" /c esentutl.exe /y "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
    /d "%temp%\T1555.003_Login_Data.tmp"
```
Which resolved at runtime (SYSTEM context) to:
```
esentutl.exe /y "C:\Windows\system32\config\systemprofile\AppData\Local\
    Google\Chrome\User Data\Default\Login Data"
    /d "C:\Windows\TEMP\T1555.003_Login_Data.tmp"
```

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033)
- `cmd.exe` launching `esentutl.exe` (T1059.003 on cmd)
- `esentutl.exe` itself (tagged `T1564.004` — NTFS File Attributes — by the sysmon-modular rule matching `esentutl` for its NTFS stream manipulation capability)

**Security exit codes — notable:**
- `esentutl.exe` exited `0xfffffc01` (decimal -1023) — this is the esentutl error code for file not found or inaccessible source. Chrome is not installed at the SYSTEM account's `%LOCALAPPDATA%` path, so the source database did not exist.
- `cmd.exe` also exited `0xfffffc01` (propagated from esentutl).

**Sysmon EID=1 on esentutl:** The esentutl process was captured in Sysmon EID=1, unlike many other binaries in these tests, because `esentutl` matches the sysmon-modular include rules for LOLBins.

**No EID=11 for output file:** `T1555.003_Login_Data.tmp` does not appear in Sysmon EID=11 — esentutl failed before creating the output file.

## What This Dataset Does Not Contain (and Why)

**Successful Chrome database copy:** No Chrome installation exists at the SYSTEM account's `%LOCALAPPDATA%` path. esentutl's `/y` operation failed with `0xfffffc01` before any output was written. In a user-context execution with Chrome installed, the output `.tmp` file would appear in EID=11.

**Locked-file bypass demonstration:** The esentutl technique's value is bypassing Chrome's file lock when the browser is running. Since Chrome was not running and the database did not exist in the SYSTEM profile, neither the lock-bypass aspect nor a successful copy occurred.

**Defender block:** esentutl.exe is a signed Microsoft binary — Defender does not block its execution. The failure here is purely due to the missing source file. This is one of the few T1555.003 tests in this series where Defender played no blocking role and the technique could have succeeded against an appropriate target.

## Assessment

This dataset captures the esentutl LOLBin credential-database-copy technique at the process and command-line level, with execution failure due to absent target file (SYSTEM context, no Chrome). The technique is significant because it succeeds where direct file access would fail (locked Chrome database during an active browser session), uses a signed system binary, and produces only a single output file. The Sysmon EID=1 for esentutl with its full command line is the primary detection indicator. The exit code `0xfffffc01` distinguishes failed from successful execution in process termination telemetry.

## Detection Opportunities Present in This Data

- **Sysmon EID=1** for `esentutl.exe` with `/y ... Login Data /d` in the command line — this is the highest-fidelity indicator. `esentutl /y` copying `Login Data` is highly anomalous.
- **Security 4688** captures both the `cmd.exe` invocation and the resolved `esentutl.exe` command line with full paths.
- **Sysmon EID=1** tagged `T1564.004` on esentutl — the sysmon-modular tag is appropriate here; esentutl's `/vss` flag (not used here but in related variants) enables shadow copy access.
- In a successful execution, **Sysmon EID=11** would show `T1555.003_Login_Data.tmp` or equivalent being created in `%TEMP%` — a high-confidence indicator when the source path contains `Login Data`.
- Exit code `0xfffffc01` from `esentutl.exe` in Security 4689 indicates file-not-found failure — useful for distinguishing successful from failed attempts in process termination auditing.
- Detection rule: `esentutl.exe` process with command-line arguments containing `Login Data` and `/y` and `/d` — covers Chrome, Edge, and any Chromium-based browser credential database.
- Parent chain: `powershell.exe` → `cmd.exe` → `esentutl.exe` (running as SYSTEM) is anomalous; esentutl should rarely if ever be spawned from PowerShell in normal operations.
