# T1560-1: Archive Collected Data — Compress Data for Exfiltration With PowerShell

## Technique Context

T1560 covers Archive Collected Data, a pre-exfiltration technique where adversaries compress and/or encrypt data to reduce size and obscure content before exfiltrating it. Test 1 uses PowerShell's built-in `Compress-Archive` cmdlet to create a ZIP archive of the user profile directory. This is a native-tool approach with no external dependencies: the adversary uses a pre-installed Windows capability rather than staging a third-party archiving tool like WinRAR or 7-Zip. PowerShell Compress-Archive is frequently observed in ransomware staging, data theft operators, and red team engagements.

## What This Dataset Contains

The dataset spans 10 seconds (01:18:29–01:18:39 UTC) across 37 Sysmon events, 10 Security events, and 4,304 PowerShell events. The extremely high PowerShell event count reflects the recursive directory traversal and file enumeration performed by `Compress-Archive` across the user profile tree — each file operation may generate module logging events.

The ART test framework executes the test via a nested PowerShell invocation:
```
"powershell.exe" & {dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\T1560-data-ps.zip}
```

Security 4688 captures both the outer `powershell.exe` (test framework) and the inner `powershell.exe` that runs the actual Compress-Archive command, visible in the full command line. The inner PowerShell is tagged in Sysmon EID 1 as `technique_id=T1083` (File and Directory Discovery) because the `dir -Recurse` traversal triggers that rule.

Sysmon EID 11 (FileCreate) captures the creation of `C:\Windows\System32\config\systemprofile\T1560-data-ps.zip` — the actual archive output. This is direct evidence of successful archive creation under the SYSTEM profile. The rule annotation on this EID 11 event is `technique_id=T1574.010` (Services File Permissions Weakness) — a false positive from the sysmon-modular rule matching a writable location under `system32\config`, not an actual T1574 event.

Sysmon EID 17 captures three `\PSHost.*` named pipes across the multiple PowerShell instances involved. Sysmon EID 10 records the test framework PowerShell accessing its child processes.

## What This Dataset Does Not Contain (and Why)

No exfiltration activity appears. Archive creation is captured, but no network connections, cloud storage uploads, or data transfer events follow. The test isolates the collection/staging phase only.

The ZIP file contents are not visible. Windows event logging does not record file content, and the collected object access audit policy is disabled (no EID 4663 events). The destinations inside the archive — the files from `$env:USERPROFILE` — are not individually logged.

No process access to sensitive credential stores (NTDS, SAM, LSASS) is present because this test is specifically about archiving files, not credential collection.

The Security log has only 10 events (4688/4689/4703) despite the 4,304 PowerShell events. The discrepancy reflects that Security only captures new process creation/termination, while the PowerShell volume comes from the file enumeration activity generating module logging events for each pipeline stage.

## Assessment

This is one of the more complete datasets in the T1560 series: the archive was successfully created (`T1560-data-ps.zip` appears in Sysmon EID 11), the full command line is captured in Security 4688, and the recursive enumeration activity is visible through both the Sysmon EID 1 T1083 annotation and the high PowerShell event volume. Defender did not block this test — `Compress-Archive` with a system directory is normal-looking activity. The dataset is well-suited for training on file archiving behavioral patterns and for building detections around PowerShell-native compression.

## Detection Opportunities Present in This Data

- **Security 4688**: `powershell.exe` with inline `Compress-Archive -DestinationPath *.zip` in the command line, executed as SYSTEM; PowerShell invoking a recursive zip of the user profile under SYSTEM context is anomalous.
- **Sysmon EID 1**: Child `powershell.exe` tagged `technique_id=T1083` for `dir -Recurse`; the combination of recursive directory discovery immediately followed by compression is a strong staging indicator.
- **Sysmon EID 11**: `T1560-data-ps.zip` file creation in `C:\Windows\System32\config\systemprofile\`; a ZIP archive written to the SYSTEM profile directory under `system32\config` is highly suspicious regardless of the creating process.
- **PowerShell 4103/4104**: Module logging captures `Compress-Archive` with the full path and pipeline; the `dir $env:USERPROFILE -Recurse | Compress-Archive` pipeline text is a reliable detection pattern.
- **Event volume anomaly**: 4,304 PowerShell events in 10 seconds; the burst of module logging events during a compressed archiving operation is distinctive and can be used as a behavioral profile even without analyzing event content.
- **Process chain**: SYSTEM `powershell.exe` spawning a second SYSTEM `powershell.exe` with an inline script block; the double-PowerShell pattern with a compression payload is consistent with ART-style scripted execution.
