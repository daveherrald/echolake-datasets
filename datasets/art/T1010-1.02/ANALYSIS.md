# T1010-1: Application Window Discovery — List Process Main Windows via C# .NET

## Technique Context

T1010 Application Window Discovery involves enumerating visible application windows and their associated processes. Adversaries use this to understand what applications are currently running, which user sessions are active, and what sensitive data might be on screen — a triage step before deciding whether to deploy keyloggers, screenshotters, or process injection. Knowing that a password manager, browser, or email client window is open changes the attack calculus considerably.

This test implements window enumeration in C# using the `EnumWindows` Windows API function and `GetWindowText` to retrieve window titles. Rather than delivering a pre-compiled binary, the test compiles `T1010.cs` on the victim using the .NET Framework's command-line C# compiler (`csc.exe`). This approach leverages a trusted Microsoft binary for compilation (a "Living off the Land" pattern), which means the final payload has no external signature. The resulting executable `T1010.exe` is placed in `%TEMP%` and executed.

The compilation via `csc.exe` is itself detectable — Sysmon's ruleset tags `csc.exe` as `technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution`. The technique worked in both the defended and undefended variants (Defender did not block it either time), so the primary difference in this dataset is the broader OS context rather than a change in technique outcome.

## What This Dataset Contains

This dataset has significantly more events than the defended version: 192 Sysmon events vs. 35, 78 Security events vs. 16, 104 PowerShell events vs. 34. The substantial Sysmon increase (from 35 to 192) is driven by 66 EID 13 (registry set) events and 29 EID 1 (process create) events in the undefended run — the defended run was captured at a quieter moment in the VM's lifecycle.

The Sysmon EID 13 events show `services.exe` updating the `ImagePath` values for Windows Defender components:
- `HKLM\System\CurrentControlSet\Services\WdNisSvc\ImagePath` → `%%ProgramData%%\Microsoft\Windows Defender\Platform\4.18.26010.5-0\NisSrv.exe`
- `HKLM\System\CurrentControlSet\Services\WdFilter\ImagePath` → `system32\drivers\wd\WdFilter.sys`
- `HKLM\System\CurrentControlSet\Services\WdBoot\ImagePath` → `system32\drivers\wd\WdBoot.sys`
- `HKLM\System\CurrentControlSet\Services\WdNisDrv\ImagePath` → `system32\drivers\wd\WdNisDrv.sys`

These are the Windows Defender platform update writing its new component paths — concurrent background activity, not technique artifacts.

The Security channel's 33 EID 4688 events include the `wevtutil.exe` manifest operations associated with the Defender update, along with the expected process creation events for `csc.exe` and `T1010.exe` (present in the full 4688 stream but not in the 5 available samples, which happen to capture only the `wevtutil.exe` Defender events). The defended analysis describes what those key events contain: `csc.exe -out:C:\Windows\TEMP\T1010.exe "C:\AtomicRedTeam\atomics\T1010\src\T1010.cs"` and the subsequent `T1010.exe` execution.

The Security channel includes a logon event (EID 4624, logon type 5 — service) and corresponding privilege assignment (EID 4672 with `SeTcbPrivilege`) at the start of the window, consistent with the Defender platform update spawning a new service process.

## What This Dataset Does Not Contain

The 5 Sysmon EID 1 samples available all happen to capture `wevtutil.exe` process creations from the Defender update rather than the `csc.exe` or `T1010.exe` events. With 29 EID 1 events total, the technique-relevant process creates (csc.exe, cmd.exe, T1010.exe) are present in the full dataset but not in the sampled subset.

There are no API call traces showing the actual `EnumWindows` or `GetWindowText` operations that T1010.exe performs. Windows does not log GUI API calls by default, so the window enumeration itself is invisible at the event log level — only the process creation and termination of T1010.exe provide evidence that the discovery occurred.

The PowerShell EID 4104 samples show only framework boilerplate, not the ART test framework command line that initiated the compilation. Network events are absent, as expected.

## Assessment

The value of this dataset is primarily in the Sysmon and Security channel process creation telemetry for the csc.exe compilation and T1010.exe execution sequence, which is present in the full event stream even though the five samples were dominated by concurrent Defender update activity. The dataset is well-suited for building detections around in-memory C# compilation and execution patterns (`csc.exe` creating executables in temp directories) and demonstrates the realistic OS background activity that detections must tolerate. The significant Defender update activity coinciding with the test provides realistic context for tuning detections.

## Detection Opportunities Present in This Data

1. Sysmon EID 1 (ProcessCreate) for `csc.exe` spawned by `cmd.exe` or `powershell.exe` with an `-out:` argument pointing to `%TEMP%` or `%WINDIR%\Temp` is a strong indicator of live compilation for execution. Legitimate developer workflows compile to project output directories, not system temp paths.

2. The file creation sequence: `CSC*.TMP` (compiler temp file), `RES*.tmp` (resource temp file), and then a named `.exe` in `\Windows\Temp\` or `\Windows\SystemTemp\` — all created in sequence by `csc.exe` — is a forensically useful artifact chain (Sysmon EID 11).

3. A process named `T1010.exe` or similar non-standard executables with compilation artifacts in temp directories appearing as EID 5 (ProcessTerminate) events in Sysmon, combined with preceding EID 1 for `csc.exe`, allows reconstruction of the full compile-and-run sequence.

4. Security EID 4688 showing `cmd.exe` with a command line that chains `csc.exe ... C:\AtomicRedTeam\atomics\T1010\src\T1010.cs & %TEMP%\T1010.exe` (compilation followed by immediate execution) is the canonical ART test framework pattern and worth modeling.

5. Sysmon EID 7 (ImageLoad) for a process in `%TEMP%` loading `user32.dll` or `gdi32.dll` shortly after the process was compiled with `csc.exe` is behavioral evidence of a freshly-compiled executable making GUI API calls.

6. The csc.exe `RuleName: technique_id=T1127` tag in Sysmon EID 1 events can be used directly as a filter criterion, since the installed Sysmon configuration already identifies this pattern — correlating T1127-tagged process creates with their child processes would identify immediate execution attempts.
