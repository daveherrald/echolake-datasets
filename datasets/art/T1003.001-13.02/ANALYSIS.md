# T1003.001-13: LSASS Memory — Dump LSASS.exe using lolbin rdrleakdiag.exe

## Technique Context

`rdrleakdiag.exe` is a Windows diagnostic tool shipped in `C:\Windows\System32\` whose stated purpose is to diagnose memory leaks in the Redirector (rdr) subsystem. Like many Windows diagnostic utilities, it accepts a PID argument and can produce a full memory dump of any process it targets — including LSASS — when executed with sufficient privileges. This LOLBin approach is attractive because the binary is present on every Windows system, is signed by Microsoft, and was historically overlooked by many detection rules that focus on known tools like ProcDump, Task Manager, or comsvcs.dll.

The ART invocation uses PowerShell to dynamically locate the binary and resolve the LSASS PID: `& $binary_path /p $lsass_pid /o $env:TEMP\t1003.001-13-rdrleakdiag /fullmemdmp /wait 1`. The `/fullmemdmp` flag requests a complete memory dump rather than a summary, and `/wait 1` tells the tool to wait one second after attaching before creating the dump. The output is written to a directory under `%TEMP%` rather than a single file.

Detection for this variant requires awareness of `rdrleakdiag.exe` as a process creation event with suspicious arguments, as it doesn't appear in most production detection rule sets. The underlying LSASS access event (Sysmon EID 10) remains the strongest universal indicator. The defended version showed `rdrleakdiag.exe` actually reaching process creation (visible in Security EID 4688) before Defender intervened. The undefended run should show the complete execution including LSASS access.

## What This Dataset Contains

This is one of the smaller datasets in the collection with only 33 Sysmon events (16 EID 7, 5 EID 11, 5 EID 10, 4 EID 1, 3 EID 17) — a stark contrast to most other T1003.001 tests that have thousands of Sysmon events. This small count means the 20-event sample captures a high proportion of the attack-specific telemetry rather than being dominated by Windows Update activity.

The **Security channel** (5 EID 4688) shows the complete process chain in the 20-sample draw:
- `whoami.exe` (PID 0x60c) — pre-execution context check
- `powershell.exe` (PID 0xd28) — the attack execution process (child of test framework)
- `rdrleakdiag.exe` (PID 0x131c, spawned by PowerShell PID 0xd28) — the LOLBin itself is visible
- `whoami.exe` (PID 0x62c) — cleanup context check
- `powershell.exe` (PID 0x1350) — cleanup process

The `rdrleakdiag.exe` process creation event is directly visible in the Security channel, confirming the tool reached execution. This contrasts with the defended version where the process failed (exit status 0x1) and the sysmon-modular configuration's include-mode filtering meant `rdrleakdiag.exe` didn't appear in Sysmon EID 1 events.

The **Sysmon channel** samples include Sysmon EID 10 (Process Access) events with `SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` accessing `whoami.exe` (PID 1548) with `GrantedAccess: 0x1FFFFF`, and EID 1 (Process Create) events for both `whoami.exe` and `powershell.exe`. The 5 EID 10 events in the dataset include the process access events from the execution chain. The critical question is whether any of the 5 EID 10 events target `lsass.exe` rather than `whoami.exe` — given the small total count and that the sysmon-modular configuration uses include-mode filtering for ProcessAccess, the LSASS access may or may not have triggered an EID 10 event depending on the access mask filter configuration.

The **PowerShell channel** (102 EID 4104, 6 EID 4103) has the defended version's command line available: `"powershell.exe" & {if (Test-Path -Path "$env:SystemRoot\System32\rdrleakdiag.exe") { $binary_path = "$env:SystemRoot\System32\rdrleakdiag.exe" } ... & $binary_path /p $lsass_pid /o $env:TEMP\t1003.001-13-rdrleakdiag /fullmemdmp /wait 1`. The 6 EID 4103 events (versus 2 in the defended run) may include output from `rdrleakdiag.exe` execution.

The PowerShell EID 4103 output includes a `CommandInvocation(Write-Host): "DONE"` event, which appears in the ART test framework infrastructure and indicates the test completed without throwing an unhandled exception.

## What This Dataset Does Not Contain

The sysmon-modular configuration's include-mode filtering for ProcessCreate means that `rdrleakdiag.exe` itself does not appear in Sysmon EID 1 events — it is not in the monitored process pattern list. This means the Security EID 4688 is the only process creation record for the LOLBin.

The dump output directory at `%TEMP%\t1003.001-13-rdrleakdiag\` and its contents may appear in Sysmon EID 11 events among the 5 file creation records, but the 5 EID 11 events in the sample draw show file system writes from the test timeline, not necessarily the dump files.

The dataset does not include post-dump credential parsing. `rdrleakdiag.exe` creates the dump and exits; the workflow to extract credentials from it (typically via Mimikatz's `sekurlsa::minidump` command) is not present.

## Assessment

This dataset provides the most directly useful LOLBin detection telemetry in the T1003.001 collection for this specific tool. The Security EID 4688 record of `rdrleakdiag.exe` being spawned by `powershell.exe` is immediately actionable. Because `rdrleakdiag.exe` is rarely invoked in normal operations — and essentially never invoked from PowerShell in a production environment — its process creation event is a high-precision indicator. The dataset also provides context for the full command-line structure including the `/p`, `/o`, `/fullmemdmp`, and `/wait` arguments, enabling precise command-line pattern matching. The small Sysmon count makes this a clean dataset to work with for rule testing.

## Detection Opportunities Present in This Data

1. Security EID 4688 with `NewProcessName` containing `rdrleakdiag.exe` — this is a high-fidelity alert on its own, since `rdrleakdiag.exe` spawned interactively or from a script host is not a normal operational event.

2. Security EID 4688 with `rdrleakdiag.exe` command line containing `/p` (PID argument) and `/fullmemdmp` — the full dump flag combined with a target PID targeting LSASS's typical PID range is highly specific.

3. Sysmon EID 10 (if present in the dataset for the LSASS access) with `TargetImage` matching `lsass.exe` and `SourceImage` matching `rdrleakdiag.exe` — the classic universal LSASS dump signal, applied to a less-common tool.

4. Sysmon EID 1 with `ParentImage` being `powershell.exe` and `Image` matching any system diagnostic utility with memory dump capabilities (including `rdrleakdiag.exe`, `werfault.exe`, `createdump.exe`) — detecting diagnostic-tool-as-dumper through parent process context.

5. Sysmon EID 11 with `TargetFilename` matching a directory path under `%TEMP%` containing a subdirectory named with the `t1003` pattern or `.dmp` files created by `rdrleakdiag.exe` — the output directory naming convention in the ART test.

6. PowerShell EID 4104 script blocks containing `rdrleakdiag` or the pattern `& $binary_path /p $lsass_pid /o` — detecting the dynamic binary invocation pattern before the process creation event fires.
