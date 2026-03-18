# T1555.003-5: Credentials from Web Browsers — Simulating Access to Opera Login Data

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) covers staging of browser credential databases. Opera stores saved passwords in a SQLite database at `%APPDATA%\Opera Software\Opera Stable\Login Data`, using the same Chromium-based credential protection scheme as Google Chrome. Adversaries targeting multi-browser environments stage Opera's credential store alongside Chrome and Firefox databases to maximize credential coverage before DPAPI decryption or exfiltration.

## What This Dataset Contains

This dataset captures a PowerShell-native Copy-Item operation targeting Opera's Login Data file, run under NT AUTHORITY\SYSTEM.

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {Copy-Item "$env:APPDATA\Opera Software\Opera Stable\Login Data"
    -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads"}
```

**PowerShell script block logging (4104):**
- The full script block captured verbatim in two 4104 events, exposing `$env:APPDATA\Opera Software\Opera Stable\Login Data` as the source path and `ExternalPayloads` as the destination.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (tagged T1033) — ART test framework identity check.
- Child `powershell.exe` for the staging block (tagged T1059.001).

**Sysmon EID=10 (Process Access):**
- Parent PowerShell accessing child — tagged T1055.001; sysmon-modular cross-process handle heuristic.

**Sysmon EID=11 (File Created):**
- `StartupProfileData-Interactive` and `StartupProfileData-NonInteractive` in the SYSTEM PowerShell profile — standard startup artifacts. No Opera Login Data appears in the ExternalPayloads destination.

**Security exit codes:**
- Child `powershell.exe` exited `0x0` — silently completed. Copy-Item found no source file at `%APPDATA%\Opera Software\Opera Stable\Login Data` under the SYSTEM account (Opera not installed in the SYSTEM profile).

## What This Dataset Does Not Contain (and Why)

**Actual Opera Login Data copy:** Opera installs per-user; the SYSTEM account's `%APPDATA%` contains no Opera installation. Copy-Item silently did nothing. No EID=11 for ExternalPayloads, no actual credential file staged.

**Defender block:** Staging a file by path with Copy-Item is not flagged as malicious by Windows Defender. The exit code of `0x0` confirms no block occurred.

**File read events:** Object access auditing is disabled; even a successful copy would not generate read events.

**Difference from T1555.003-4:** Test 4 targets Chrome (`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`); this test targets Opera (`%APPDATA%\Opera Software\Opera Stable\Login Data`). The telemetry structure and outcome are identical — the distinguishing element is the browser-specific path in the script block and command line.

## Assessment

Like T1555.003-4, this test was a technical no-op due to the SYSTEM account context. Its value is as a source of labeled telemetry showing the exact path used for Opera credential staging. Combined with test 4 (Chrome) and test 10 (multi-browser staging), this dataset demonstrates the breadth of browser targets adversaries use, each requiring path-specific detection coverage.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block** contains `Opera Software\Opera Stable\Login Data` — a high-fidelity string match for Opera credential staging.
- **Security 4688 / Sysmon EID=1** capture the `Copy-Item` with the Opera path in the command line, detectable without script block logging.
- The `%APPDATA%\Opera Software\Opera Stable\Login Data` path can be added to file-path watchlists alongside Chrome and Firefox paths.
- In a user-context execution, an **EID=11** creating a file at `ExternalPayloads\Login Data` would provide a confirmatory indicator.
- Detection rules should cover both `%APPDATA%` and `%LOCALAPPDATA%` paths for multi-browser credential staging, since Opera uses `%APPDATA%` while Chrome uses `%LOCALAPPDATA%`.
