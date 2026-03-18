# T1552-2: Unsecured Credentials — Search for Passwords in PowerShell History

## Technique Context

Unsecured Credentials (T1552) covers the discovery and extraction of credentials stored insecurely on a system. This test searches PSReadLine command history files — which are plaintext logs of all previously typed PowerShell commands — for password-related keywords. History files are stored per-user at `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` and are a frequently overlooked credential store that may contain passwords typed directly into PowerShell sessions.

## What This Dataset Contains

The attack is a single PowerShell one-liner recorded verbatim in EID 4104:

> `ls -R C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | Select-String "password", "-p", "key", "pwd", "pass"`

This searches history files across all user profiles for common password-related strings. The same script block appears twice in the 4104 log (the outer `& {...}` and the inner block), which is normal ART test framework behavior. The PowerShell module log (EID 4103) records the command execution with full parameter binding:

- `Get-ChildItem` with `-Recurse` on the PSReadLine path
- `Select-String` with `Pattern: "password, -p, key, pwd, pass"`

This confirms the search executed. No matching lines are reported in the module log output, indicating either no history files existed for non-SYSTEM users on this workstation, or none contained the keyword patterns — the machine context is `NT AUTHORITY\SYSTEM` with `ACME-WS02$` as the account name.

The Sysmon dataset has 26 events: 17 EID 7 image loads (single PowerShell instance loading .NET CLR and Defender DLLs), 3 EID 11 file creates (PowerShell profile data), 2 EID 17 named pipe creates, and 2 EID 10 ProcessAccess events. A `whoami.exe` process is created (Sysmon EID 1 tagged `technique_id=T1033`) — the standard ART test framework identity check. Security logs show 10 events covering `whoami.exe` and `powershell.exe` create/exit events plus a `4703` token right adjustment.

## What This Dataset Does Not Contain (and Why)

There are no file read events for the history files themselves. The audit policy has `object_access: none`, which means file system read operations are not audited. Sysmon EID 11 captures file creates and overwrites but not reads. PSReadLine history searches are fundamentally read operations, so the actual file access is invisible in this telemetry beyond the PowerShell command log confirming the search was attempted. There are no credential exfiltration events because the test found no matching content. There are no network events because this technique operates entirely on local files.

## Assessment

This is a lightweight credential discovery dataset. The primary detection surface is entirely within PowerShell logging: the script block text and the module log parameter binding provide full visibility into what was searched and where. The absence of file access auditing means the detection must be based on command intent rather than observed file reads. The dataset illustrates that PSReadLine history searches leave clear PowerShell-layer evidence while generating minimal OS-level noise.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block**: The exact search pattern — `Select-String "password", "-p", "key", "pwd", "pass"` against PSReadLine history path — is a well-known offensive pattern. The wildcard path `C:\Users\*\AppData\Roaming\...` targeting all user profiles is anomalous.
- **PowerShell 4103 module log**: `Get-ChildItem -Recurse` on `*\PSReadLine\ConsoleHost_history.txt` with `Select-String` is detectable as a named command invocation sequence even without script block logging enabled.
- **Security 4688 command line**: The powershell.exe invocation command line contains the full search expression.
- **Process context**: Execution as `NT AUTHORITY\SYSTEM` running a user credential search is inherently suspicious — SYSTEM processes have no legitimate reason to search user PSReadLine history.
- **PSReadLine path as a search target**: Alerting on any process opening or reading `*\PSReadLine\ConsoleHost_history.txt` in bulk (multiple user profiles) would catch this technique even without command-line logging.
