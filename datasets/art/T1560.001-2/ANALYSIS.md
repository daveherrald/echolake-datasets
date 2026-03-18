# T1560.001-2: Archive via Utility — Compress Data and lock with password for Exfiltration with winrar

## Technique Context

T1560.001 (Archive via Utility) covers adversary use of compression and archival tools to stage collected data before exfiltration. Password-protecting the archive adds a layer of data-at-rest encryption that frustrates incident responders attempting to inspect contents. WinRAR is one of the most widely deployed commercial archive utilities on Windows and is commonly abused for this purpose in real-world intrusions.

## What This Dataset Contains

The dataset captures 71 events across Sysmon, Security, and PowerShell logs collected during a 5-second window on 2026-03-14 at 01:19 UTC.

The substantive technique activity is documented in Security EID 4688 (process creation with command-line logging). The archiving command was launched by PowerShell and shows the full intent:

```
"cmd.exe" /c mkdir .\tmp\victim-files & cd .\tmp\victim-files & echo "This file will be encrypted" > .\encrypted_file.txt & "%programfiles%/WinRAR/Rar.exe" a -hp"blue" hello.rar & dir
```

Key observations from the data:

- Sysmon EID 1 captures `whoami.exe` (RuleName: `technique_id=T1033`) and `cmd.exe` (RuleName: `technique_id=T1083`) spawned by `powershell.exe` as NT AUTHORITY\SYSTEM.
- Sysmon EID 11 records a file creation: `C:\Windows\Temp\tmp\victim-files\encrypted_file.txt` created by `cmd.exe`, confirming the victim file staging path.
- Sysmon EID 7 (ImageLoad) fires multiple times for PowerShell's DLL load chain, tagged with rule annotations for T1055 (Process Injection) and T1574.002 (DLL Side-Loading) — these are Sysmon's heuristic rule labels on standard PowerShell DLLs, not indicators of actual injection.
- Sysmon EID 10 (ProcessAccess) fires with `technique_id=T1055.001` targeting `whoami.exe` from PowerShell — this is an ART test framework artifact from PowerShell's use of `System.Diagnostics.Process` to capture output.
- Sysmon EID 17 records a named pipe creation (`\PSHost.*`) by PowerShell, a standard artifact of the ART execution test framework.
- Security EID 4703 (token right adjusted) appears as a side-effect of the SYSTEM process spawning child processes.
- PowerShell EID 4104 events are dominated by PowerShell internal error-handling scriptblocks: `{ Set-StrictMode -Version 1; $_.PSMessageDetails }`, `{ Set-StrictMode -Version 1; $_.ErrorCategory_Message }`, and similar — these are boilerplate emitted by the ART framework on every test invocation.
- PowerShell EID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`, another consistent ART test framework artifact.

WinRAR itself does not appear as a process creation event in the Sysmon data, because the sysmon-modular include-mode configuration does not match `Rar.exe` against any known-suspicious process rules. The Security log (4688) does capture the parent `cmd.exe` with the full WinRAR invocation in its command line.

## What This Dataset Does Not Contain (and Why)

**No Rar.exe or WinRAR process creation in Sysmon (EID 1).** The sysmon-modular config uses include-mode ProcessCreate rules targeting known-suspicious patterns (LOLBins, specific tool names, etc.). `Rar.exe` does not match any include rule, so Sysmon EID 1 is absent for the archiver itself. Security EID 4688 covers this gap with command-line logging enabled.

**No archive output file creation in Sysmon (EID 11).** The `hello.rar` output file is not present as a Sysmon FileCreate event. The Sysmon FileCreate configuration does not include a rule matching `.rar` output paths in temp directories.

**No network activity.** This test stages data for exfiltration but does not transmit it. No Sysmon EID 3 (NetworkConnect) or DNS query events are present.

**No evidence of WinRAR being present pre-test.** The test assumes WinRAR is installed at `%programfiles%/WinRAR/Rar.exe`. If the binary were absent, the cmd chain would fail silently after the `mkdir` and `echo` steps.

## Assessment

This dataset successfully captures the command-line intent of a password-protected WinRAR archive operation via Security EID 4688 with full command-line logging. The WinRAR invocation including the `-hp"blue"` password switch is clearly visible. The Sysmon data provides supporting process ancestry (PowerShell > cmd > whoami) and victim file creation on disk. The PowerShell log is dominated by ART test framework boilerplate with no technique-specific content. The dataset represents a realistic, noisy capture of this technique as it would appear in an environment with aggressive Sysmon include-mode filtering — the archiver binary itself is invisible to Sysmon but fully captured in the Security log.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` process creation with command line containing `Rar.exe` and `-hp` (password flag) as a child of `powershell.exe` running as SYSTEM.
- **Security EID 4688**: Presence of `-hp"` pattern in any process command line, indicating WinRAR password-protected archive creation.
- **Sysmon EID 11**: File creation in a temp path ending in `\victim-files\`, indicating staged file collection prior to archival.
- **Sysmon EID 1**: `whoami.exe` executing as SYSTEM with `powershell.exe` as parent — consistent with post-exploitation reconnaissance immediately preceding data collection activity.
- **Correlation**: Sequence of `whoami.exe` + `cmd.exe` + file creation in a staging directory within seconds, all under SYSTEM, is a high-fidelity behavioral pattern for automated data staging.
