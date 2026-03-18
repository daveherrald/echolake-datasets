# T1555.003-4: Credentials from Web Browsers — Simulating Access to Chrome Login Data

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes techniques that copy or access browser credential stores without executing a dedicated credential-dumping binary. Chrome stores saved passwords in a SQLite database at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` and a secondary per-account file (`Login Data For Account`). Adversaries staging these files — copying them out of the locked user profile to a controlled location — can then decrypt DPAPI-protected password fields offline or exfiltrate the raw database. This approach avoids launching a flagged tool and may evade AV controls that focus on known-bad binaries.

## What This Dataset Contains

This dataset captures a PowerShell-native Copy-Item operation that attempts to stage Chrome's Login Data files to an exfiltration staging directory.

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads"
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data For Account"
    -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads"}
```

**PowerShell script block logging (4104):**
- The full script block above was captured verbatim in two 4104 events (the `& {…}` form and the bare `{…}` form), exposing the exact source and destination paths.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (tagged T1033) — ART test framework identity check.
- The `powershell.exe` child spawned for the Copy-Item block (tagged T1059.001).

**Sysmon EID=10 (Process Access):**
- Parent PowerShell accessing the child PowerShell process — tagged T1055.001; this is the sysmon-modular cross-process handle heuristic.

**Sysmon EID=11 (File Created):**
- `StartupProfileData-Interactive` and `StartupProfileData-NonInteractive` under the SYSTEM PowerShell profile — standard PowerShell startup artifacts.
- No Chrome Login Data file appears in EID=11 for the ExternalPayloads destination, because the Chrome profile belongs to a user account not currently logged in (the test runs as SYSTEM) and Chrome's `Login Data` file was absent or inaccessible at that path.

**Security exit codes:**
- The child `powershell.exe` exited `0x0` (success) — PowerShell completed without error, meaning either the Copy-Item ran and found nothing, or silently failed with no error. No Defender block; file copy of browser data is not itself a malicious binary execution.

## What This Dataset Does Not Contain (and Why)

**Actual Chrome Login Data file copy:** The SYSTEM account runs in `C:\Windows\system32\config\systemprofile\AppData\Local\` — not in a typical user's `%LOCALAPPDATA%`. Chrome is installed per-user; no Chrome profile exists at the SYSTEM account's `%LOCALAPPDATA%` path. The Copy-Item silently found no source file. No EID=11 events show files written to `ExternalPayloads`.

**File read/object access events:** Audit policy has object access disabled; even if Chrome's Login Data had been found, no file-read events would appear.

**DPAPI decryption:** The test only stages files; decryption would be a separate subsequent step not captured here.

**Defender alerts:** Windows Defender does not flag PowerShell Copy-Item of browser credential files without additional behavioral context; no block occurred.

## Assessment

This dataset represents a clean execution of a file-staging technique where the attack attempt was a technical no-op — no Chrome installation existed at the SYSTEM profile's `%LOCALAPPDATA%` path. However, the telemetry value is high: the full command line and script block text are captured, exposing exactly which browser credential paths were targeted. The pattern `Copy-Item ... "Login Data" ... ExternalPayloads` is a high-fidelity detection opportunity applicable to real attacks where a user-context session does have Chrome installed.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block** contains the literal string `Login Data` and `ExternalPayloads` — these strings in script block text are reliable detection signals for browser credential staging.
- **Security 4688 / Sysmon EID=1** both capture the `powershell.exe` command line with `Copy-Item` and `Login Data` — detectable without script block logging.
- **Sysmon EID=1** tagged `T1059.001` on a PowerShell child from a SYSTEM-context parent is a behavioral baseline deviation worth alerting on.
- In a real user-context execution, an **EID=11 (File Created)** for `ExternalPayloads\Login Data` would provide a high-confidence file system indicator.
- The `& { Copy-Item ... Login Data }` pattern in PowerShell can be detected with string matching on 4103 module logging payload or 4104 script block text targeting `Login Data`, `logins.json`, or `key4.db`.
