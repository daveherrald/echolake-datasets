# T1518-5: Software Discovery — WinPwn - DotNet

## Technique Context

T1518 (Software Discovery) includes tooling-assisted .NET component enumeration as a post-compromise reconnaissance step. WinPwn's `DotNet` function enumerates installed .NET Framework and .NET Core/5+ runtimes, helping adversaries assess which payload formats and runtime-dependent tools are viable on the target. Like the `Dotnetsearch` function in T1518-4, the delivery mechanism is a `net.webclient.downloadstring` cradle fetching WinPwn directly from GitHub via `Invoke-Expression`.

## What This Dataset Contains

This dataset contains no event data. The `bundled` list in `dataset.yaml` is empty (`bundled: []`) and the `data/` directory is empty. The `verification.source_counts` and `verification.dest_counts` fields are both empty objects (`{}`), confirming no events were collected during the 10-second test window (epoch 1773442116–1773442126).

The test executed on ACME-WS02 (VM 302, 192.168.4.12) at 22:48:36–22:48:46 UTC on 2026-03-13. The absence of events is itself informative: either Windows Defender blocked the download before any process creation was logged, or the Cribl Edge collection pipeline did not flush events within the collection window for this test.

Given the pattern observed in T1518-4 (the identical `Dotnetsearch` variant of this test), the most likely explanation is that Defender's real-time protection blocked the WinPwn download cradle before a child process was spawned, and the parent `powershell.exe` process was not matched by sysmon-modular's include-mode ProcessCreate filter. The ART test framework PowerShell (`powershell.exe` without distinguishing arguments) would not be captured by Sysmon's include-mode filter, and if no child process was spawned, no Event 1 would be generated.

## What This Dataset Does Not Contain

- No Sysmon events of any kind.
- No Security event log entries.
- No PowerShell script block or module logging events.
- No evidence of the WinPwn download, AMSI block, or .NET enumeration.

## Assessment

This dataset has no detection value in its current form. It represents a collection gap rather than a clean Defender-blocked scenario — for comparison, the T1518-4 test (same framework, different function) produced 31 Sysmon events, 10 security events, and 51 PowerShell events including an explicit AMSI block error (PowerShell 4100). The absence of even test framework-level telemetry (no `whoami.exe` from the ART pre-check, no `Set-ExecutionPolicy` in the PowerShell log) suggests the test may not have executed correctly or the events were lost in the collection pipeline.

This dataset should be regenerated with confirmed instrumentation before being used for detection engineering. Paired against T1518-4, the `DotNet` and `Dotnetsearch` WinPwn functions should produce nearly identical telemetry patterns.

## Detection Opportunities Present in This Data

No detection opportunities can be demonstrated from this dataset. Refer to T1518-4 for detection guidance applicable to the WinPwn download cradle pattern, which is common to both tests.
