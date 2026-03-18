# T1552.001-4: Credentials In Files — Extracting Passwords with findstr

## Technique Context

MITRE ATT&CK T1552.001 (Credentials in Files) covers adversary searches of the local filesystem for files containing plaintext or encoded credentials. Test 4 uses two classic Windows tools in combination: `findstr.exe` with the `/si` (case-insensitive, recursive) flag searching for the string "pass" across common document types, and PowerShell's `Select-String` doing the same over the entire drive. This pattern is widely observed in real intrusions and is among the simplest credential-hunting techniques available on Windows. The commands run without any external dependencies and leave a clear trail through process creation and command-line logging.

## What This Dataset Contains

The dataset spans approximately two minutes (00:22:52–00:24:57 UTC) and contains 11,282 events across five log sources.

**The core technique is captured in full.** The Atomic Red Team test framework executed:

```
powershell.exe & {findstr /si pass *.xml *.doc *.txt *.xls
ls -R | select-string -ErrorAction SilentlyContinue -Pattern password}
```

The Sysmon ProcessCreate chain is visible: PowerShell (PID 6348) is spawned from the test framework process (PID 6244) with the complete command line in the `CommandLine` field, tagged `technique_id=T1083,technique_name=File and Directory Discovery`. A child `findstr.exe` (PID 4280) is immediately created with `CommandLine: "C:\Windows\system32\findstr.exe" /si pass *.xml *.doc *.txt *.xls`, also tagged T1083.

Security 4688 events independently confirm both the PowerShell and `findstr.exe` process launches with full command-line detail. Security 4689 events record both processes exiting with status 0x0 (success), indicating the search completed.

The PowerShell log (EID 4104 script block logging) preserves the exact script block text:

```
& {findstr /si pass *.xml *.doc *.txt *.xls
ls -R | select-string -ErrorAction SilentlyContinue -Pattern password}
```

A preceding EID 4103 module log records `Set-ExecutionPolicy Bypass` — the ART test framework boilerplate that appears before every test. Numerous repetitive EID 4103 `CommandInvocation(Get-Location)` entries are generated as `ls -R` recursively enumerates directories; these represent the mechanics of the search across the filesystem.

Sysmon also records DLL image loads (EID 7) tagged T1055 and T1059.001 for the PowerShell process, a named pipe creation (EID 17, `\PSHost.134...`), and a process access event (EID 10) from the parent test framework process.

The system.jsonl (1 event, EID 7040) and wmi.jsonl (1 event, EID 5858) contain unrelated OS housekeeping events collected during the window.

## What This Dataset Does Not Contain (and Why)

**No credential output.** `findstr` returns matches to stdout; no file is written and object access auditing is not enabled, so the actual content of any matching files is not captured.

**findstr.exe does not appear in Sysmon's ProcessCreate data independently** at first glance — it does appear (EID 1, PID 4280) but only because the sysmon-modular config includes T1083 (File and Directory Discovery) LOLBin rules that catch it. Not all child processes of PowerShell would be captured under a stricter include-mode config.

**No network events.** The technique is purely local filesystem enumeration.

**No file read telemetry.** Object access auditing (`object_access: none`) means there is no record of which files were actually opened or read. The search ran but file access is invisible in this dataset.

**No WMI activity beyond the background EID 5858.** The WMI event is unrelated to the technique.

## Assessment

This dataset provides a clean, complete capture of the findstr-based credential search pattern. Both the Sysmon and Security process creation chains are intact with full command lines. Script block logging captures the exact code. The two-minute window captures the full execution arc — the recursive search over the `C:\Windows\TEMP\` working directory took approximately two minutes before producing a zero exit code. The large PowerShell event count (11,227 bundled from 26,448 source) reflects the repetitive `Get-Location` module log entries generated during recursive directory enumeration; analysts building detections should be aware this technique generates significant PS module log volume.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `findstr.exe` launched with `/si` and password-related search terms (`pass`, `password`, `pwd`, etc.) targeting document extensions. The combination of `/si` with credential keywords is highly specific.
- **Sysmon EID 1**: PowerShell spawning `findstr.exe` as a child process is unusual in normal operations.
- **PowerShell EID 4104**: Script block containing both `findstr` with `/si` and `Select-String -Pattern password` in the same block. The exact ART string is `findstr /si pass *.xml *.doc *.txt *.xls`.
- **PowerShell EID 4103**: `Set-ExecutionPolicy Bypass` combined with subsequent credential-search commands (test framework indicator, but also legitimately suspicious).
- **Security EID 4689**: Process exit with status 0x0 confirms the search ran to completion without error, which may be relevant for behavioral baselining.
- **Command-line pattern**: The `/si` flag combined with multi-extension targeting (`*.xml *.doc *.txt *.xls`) is a strong behavioral signature regardless of the keyword used.
