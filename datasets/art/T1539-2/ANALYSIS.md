# T1539-2: Steal Web Session Cookie — Steal Chrome Cookies (Windows)

## Technique Context

T1539 (Steal Web Session Cookie) covers adversary techniques for obtaining web session tokens that can be replayed to authenticate to online services without knowing passwords, bypassing multi-factor authentication. On Windows, Chrome stores cookies in a SQLite database at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies`. Attackers — including commodity infostealer malware and targeted access brokers — read this file directly (after killing Chrome to release its file lock) using SQLite tooling or custom code. Detection typically targets: process accessing the Chrome `Cookies` file, suspicious processes reading from Chrome's profile directory, and execution of SQLite tooling against browser databases.

## What This Dataset Contains

The test stops Chrome, then queries the Chrome Cookies database using an `sqlite3.exe` binary pre-staged in the ART ExternalPayloads directory:

```powershell
stop-process -name "chrome" -force -erroraction silentlycontinue
"select host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly from [Cookies];" | cmd /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\sqlite-tools-win32-x86-3380200\sqlite3.exe "$env:localappdata\Google\Chrome\User Data\Default\Network\Cookies" | out-file -filepath "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1539ChromeCookies.txt"
```

This script block appears verbatim in PowerShell Event ID 4104 (Script Block Logging). Security 4688 and Sysmon Event ID 1 record `powershell.exe` → `powershell.exe` (technique block) → `cmd.exe`, with the full command line including the SQLite query string and the target Cookies file path. The `cmd.exe` process resolves the `$env:localappdata` path under the SYSTEM context, producing the actual path `C:\Windows\system32\config\systemprofile\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`. Sysmon Event ID 1 captures `sqlite3.exe` invocation details through the `cmd.exe` command line.

The `cmd.exe` process exited `0x1` (failure). Chrome is not installed in the SYSTEM profile path used during execution, so `sqlite3.exe` found no database to query and the output file would be empty or absent. The attempt telemetry is fully present even though no cookies were extracted.

## What This Dataset Does Not Contain

**No Sysmon ProcessCreate for `sqlite3.exe` itself.** The sysmon-modular include-mode filter does not match `sqlite3.exe` by name or path, so no Sysmon Event ID 1 appears for the SQLite process — only for the parent `cmd.exe`. Security 4688 also does not capture `sqlite3.exe` as a distinct process creation event in this dataset, as the audit policy's command-line logging captures it only within the `cmd.exe` invocation line.

**No file access events for the Chrome Cookies database.** Object access auditing is disabled (`object_access: none`), so there are no 4663 (object access) events showing the read attempt against the Cookies file.

**No successful cookie extraction.** Chrome is not installed in the SYSTEM user profile path, so the database does not exist at the queried path.

## Assessment

This dataset offers strong command-line and script-block detection opportunities despite the failed execution. The PowerShell 4104 event captures the entire technique including the SQL query string targeting the Cookies table, the path to `sqlite3.exe`, and the output file path. The `cmd.exe` command line in 4688 confirms the tool invocation. The dataset is limited by the absence of file access auditing and the sysmon filter gap for `sqlite3.exe`. Enabling object access auditing on the Chrome profile directory or adding a Sysmon include rule for sqlite3 would significantly improve telemetry quality.

## Detection Opportunities Present in This Data

1. **PowerShell Event ID 4104**: Script block containing `Chrome\User Data` and `Cookies` — direct reference to Chrome's cookie store.
2. **PowerShell Event ID 4104**: Script block containing a SQL `SELECT` against `[Cookies]` with cookie column names — infostealer-style query pattern.
3. **PowerShell Event ID 4104**: `stop-process -name "chrome"` combined with subsequent file access to Chrome's profile directory — kill-and-read pattern for locked database theft.
4. **Security 4688 / Sysmon Event ID 1**: `cmd.exe` with `sqlite3.exe` in command line targeting a path containing `Chrome\User Data` — SQLite tooling against browser database.
5. **Sysmon Event ID 1**: `powershell.exe` with `out-file` writing to a path containing `T1539` or `Cookies` in the filename — staged output file creation.
6. **File path pattern in command line**: Any process command line referencing `\Google\Chrome\User Data\Default\Network\Cookies` — highly specific indicator for this technique regardless of tool used.
