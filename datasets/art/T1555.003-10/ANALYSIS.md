# T1555.003-10: Credentials from Web Browsers — Stage Popular Credential Files for Exfiltration

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) encompasses multi-browser credential staging — a common adversary technique that collects credential database files from all popular browsers in a single pass before exfiltration. This test implements a comprehensive PowerShell script that checks for and copies credential files from Firefox (`key4.db`, `logins.json`), Chrome (`Login Data`, `Login Data For Account`), Opera (`Login Data`), and Edge (`Login Data`), then compresses the collected files into a ZIP archive for staged exfiltration. This pattern mirrors real-world infostealers and post-exploitation frameworks that enumerate browser stores systematically.

## What This Dataset Contains

This dataset captures the complete execution of a multi-browser credential staging script run as NT AUTHORITY\SYSTEM.

**Full script block (PowerShell 4104):**
```powershell
$exfil_folder = "$env:temp\T1555.003"
if (test-path "$exfil_folder") {} else {new-item -path "$env:temp" -Name "T1555.003" -ItemType "directory" -force}
$FirefoxCredsLocation = get-childitem -path "$env:appdata\Mozilla\Firefox\Profiles\*.default-release\"
if (test-path "$FirefoxCredsLocation\key4.db") {copy-item "$FirefoxCredsLocation\key4.db" -destination "$exfil_folder\T1555.003Firefox_key4.db"} else {}
if (test-path "$FirefoxCredsLocation\logins.json") {copy-item "$FirefoxCredsLocation\logins.json" -destination "$exfil_folder\T1555.003Firefox_logins.json"} else {}
if (test-path "$env:localappdata\Google\Chrome\User Data\Default\Login Data") { ... }
if (test-path "$env:localappdata\Google\Chrome\User Data\Default\Login Data For Account") { ... }
if (test-path "$env:appdata\Opera Software\Opera Stable\Login Data") { ... }
if (test-path "$env:localappdata/Microsoft/Edge/User Data/Default/Login Data") { ... }
compress-archive -path "$exfil_folder" -destinationpath "$exfil_folder.zip" -force
```

The complete script block appeared verbatim in 4104 events, fully exposing all targeted browser paths and the ZIP compression step.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033) — ART test framework identity check.
- Child `powershell.exe` for the staging block (T1059.001).
- A second `powershell.exe` for the `compress-archive` invocation (T1083 — File and Directory Discovery tag on the `dir` operations).

**Sysmon EID=11 (File Created) — notable:**
- `C:\Windows\Temp\T1555.003` — the staging directory was created, tagged with rule `technique_id=T1574.010` (Services File Permissions Weakness) — a sysmon-modular false-positive tag based on the write location matching a Temp path pattern.
- `C:\Windows\Temp\T1555.003.zip` — the ZIP archive was created, also tagged T1574.010.
- `StartupProfileData-*` files — standard PowerShell startup artifacts.

**Security exit codes:** All `0x0` — the script ran to completion successfully.

**Sysmon EID=10 (Process Access):** Parent PowerShell accessing child process handles — sysmon-modular T1055.001 heuristic.

## What This Dataset Does Not Contain (and Why)

**Browser credential files in the ZIP:** The SYSTEM account has no Chrome, Firefox, Opera, or Edge profiles at the standard per-user paths. The script's `if (test-path ...)` guards evaluated to false for all browsers, so no credential files were copied. The staging directory and ZIP archive were created but are empty.

**File contents:** Audit object access is disabled; even if credential files had been found, no read events would appear. The ZIP file is present in EID=11 but its contents are not logged.

**Defender block:** Windows Defender did not block this execution — the script uses only built-in PowerShell cmdlets (Get-ChildItem, Copy-Item, Compress-Archive) and accesses no protected process memory. AV blocking here would require behavioral heuristics, not signature matching.

## Assessment

Despite no credential files being present, this dataset captures the full adversary script logic, the staging directory creation, and the ZIP archive creation — three distinct observable artifacts. The script is representative of real infostealer staging patterns that target all major browsers in a single operation. The ZIP creation at `C:\Windows\Temp\T1555.003.zip` is a particularly clean indicator, as the path embeds the ATT&CK technique ID (an ART artifact), but in real attacks equivalent staging directories under `%TEMP%` with innocuous names would produce similar EID=11 signals.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block** contains all targeted browser paths (`key4.db`, `logins.json`, `Login Data`, `Login Data For Account`) plus `compress-archive` — a combination that is highly anomalous and warrants immediate alert.
- **Sysmon EID=11** shows creation of `C:\Windows\Temp\T1555.003` (staging directory) and `.zip` archive — file creation under Temp by PowerShell is a behavioral indicator, especially with names matching browser credential staging patterns.
- **Security 4688 / Sysmon EID=1** capture the full `& { $exfil_folder = ... compress-archive }` command line.
- Detection rule: PowerShell process creating a ZIP file in `%TEMP%` after accessing paths containing `Login Data` or `key4.db` — high-fidelity multi-step behavioral correlation.
- The EID=11 Sysmon tag `T1574.010` is a false-positive from sysmon-modular's path-based rules; do not use this tag for this technique.
