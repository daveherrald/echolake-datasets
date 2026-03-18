# T1518.001-6: Security Software Discovery — Sysmon Service Detection via fltMC

## Technique Context

T1518.001 (Security Software Discovery) covers adversary enumeration of defensive tooling. This test targets a specific and reliable method for detecting Sysmon: `fltMC.exe` — the Windows Filter Manager control utility — lists all loaded minifilter drivers, including Sysmon, which registers under altitude number `385201`. This approach works even when Sysmon's process is hidden or its service is renamed, because it operates at the kernel driver level rather than through process or service enumeration.

An adversary who knows Sysmon is present will understand that their process creations, network connections, file writes, and registry operations are being logged. Some may adjust their tradecraft to avoid Sysmon-detected operations; others may attempt to unload Sysmon using `fltMC.exe unload SysmonDrv` — making this discovery step a potential precursor to defense evasion.

In the defended variant (18 Sysmon, 14 Security, 29 PowerShell), the test ran with identical telemetry. No Defender block occurred — `fltMC.exe` is a legitimate Windows administrative utility and the command generates no AMSI hit. This undefended dataset is behaviorally identical to the defended variant; the primary difference is the execution environment, not the outcome.

## What This Dataset Contains

The dataset spans approximately 6 seconds (2026-03-17 17:06:09–17:06:15 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 142 events across three channels: 108 PowerShell, 28 Sysmon, and 6 Security.

**Security (6 events, EID 4688):** Six process creation events document the full execution chain. In order:

1. `"C:\Windows\system32\whoami.exe"` — test framework pre-flight
2. `"cmd.exe" /c fltmc.exe | findstr.exe 385201` — the core technique command, spawned by `powershell.exe`
3. `fltmc.exe` — spawned by `cmd.exe` to enumerate minifilter drivers
4. `findstr.exe 385201` — spawned by `cmd.exe` to filter the fltMC output for Sysmon's altitude
5. `"C:\Windows\system32\whoami.exe"` — post-execution test framework check
6. `"cmd.exe" /c` — the cleanup phase (empty invocation)

The complete parent-child chain is visible: `powershell.exe → cmd.exe → fltmc.exe + findstr.exe`. All processes run as `NT AUTHORITY\SYSTEM`.

**Sysmon (28 events, EIDs 1, 7, 10, 11, 13, 17, 22):** Sysmon EID 1 captures six process creations, mirroring the Security channel. Critically, `fltMC.exe` is tagged directly with `RuleName: technique_id=T1518.001,technique_name=Security Software Discovery` — the sysmon-modular configuration explicitly identifies this as a security software discovery indicator. `cmd.exe` is tagged `T1059.003` and `findstr.exe` is tagged `T1083`. The parent command line for `cmd.exe` (`"cmd.exe" /c fltmc.exe | findstr.exe 385201`) is preserved in both the EID 1 and EID 4688 records.

Sysmon EID 22 (DnsQuery) captures three DNS queries for `ACME-WS06` (the local hostname) made by `spoolsv.exe` — Print Spooler performing local hostname resolution. These are background OS events coinciding with the test window, not caused by the technique. Sysmon EID 13 (RegistryValue) captured no entries in the surfaced samples, though the EID breakdown shows 3 EID 13 records in the full dataset — likely background registry writes.

**PowerShell (108 events, EIDs 4103, 4104):** The PowerShell channel contains only ART test framework boilerplate. The technique itself was invoked via `cmd.exe` rather than inline PowerShell, so no technique-relevant script blocks appear in EID 4104. The 3 EID 4103 records capture `Set-ExecutionPolicy Bypass` and the test framework write-host `DONE`. The 105 EID 4104 records are internal PowerShell formatter stubs.

## What This Dataset Does Not Contain

- **No output of `fltMC.exe`.** The list of loaded minifilter drivers — including whether Sysmon was detected — is not captured in event logs. Only the invocation is recorded, not the response.
- **No Sysmon EID 3 (NetworkConnect).** This technique involves no network activity.
- **No technique-specific PowerShell EID 4104 content.** Because the command was passed to `cmd.exe` rather than executed inline in a PowerShell script block, no WinEvent 4104 record carries the `fltmc | findstr 385201` text. Security EID 4688 and Sysmon EID 1 are the authoritative command line sources.
- **No observable difference vs. the defended variant.** `fltMC.exe` is a signed Microsoft binary and the command generates no AMSI signal. The defended and undefended datasets for this test are expected to be functionally equivalent.

## Assessment

This dataset is one of the cleaner examples in the T1518.001 series: the complete execution chain is fully documented across two independent channels (Security EID 4688 and Sysmon EID 1), the sysmon-modular rule set directly tags the `fltMC.exe` invocation with the correct MITRE technique ID, and the command carries high-specificity content (the `385201` altitude string identifying Sysmon).

The 28 Sysmon events in the undefended run versus 18 in the defended run represents a modest increase, consistent with the longer overall dataset duration (the undefended run captured slightly more background activity). The PowerShell event counts are also similar (108 vs. 29) — the difference is primarily the higher baseline of framework-generated script blocks in the undefended run.

Because `fltMC.exe` is a legitimate administrative tool, this technique is representative of the broader LOLBin detection challenge: the indicator value lies not in the binary itself but in the specific argument (`385201`), the parent process (`cmd.exe` spawned by `powershell.exe`), and the execution context (SYSTEM, from a scripting host).

## Detection Opportunities Present in This Data

- **Sysmon EID 1 with RuleName `T1518.001`:** The sysmon-modular configuration directly tags `fltMC.exe` execution with the correct technique ID. This is one of the few cases in these datasets where the Sysmon rule labeling is semantically accurate rather than approximate.
- **Security EID 4688 command line:** `"cmd.exe" /c fltmc.exe | findstr.exe 385201` is captured verbatim. The `385201` altitude number is Sysmon-specific and its presence in a command line is a high-fidelity indicator for Sysmon-targeted enumeration.
- **Process tree:** `powershell.exe → cmd.exe → fltmc.exe + findstr.exe` is fully visible in both Security and Sysmon channels. The PowerShell-to-cmd.exe spawning pattern followed by a LOLBin invocation is a common initial triage indicator.
- **Sysmon EID 10 (ProcessAccess):** Four EID 10 events are present, tagged `T1055.001`. These fire from the parent PowerShell opening handles to child processes — a consistent test framework artifact that helps correlate which EID 1 process creations belong to the same test invocation.
