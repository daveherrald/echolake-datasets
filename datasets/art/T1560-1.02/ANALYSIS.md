# T1560-1: Archive Collected Data — Compress Data for Exfiltration With PowerShell

## Technique Context

T1560 covers Archive Collected Data, a pre-exfiltration technique where adversaries compress and/or encrypt data to reduce size and obscure content before moving it off the victim system. Test 1 uses PowerShell's built-in `Compress-Archive` cmdlet to create a ZIP archive of the user profile directory. This is a native-tool approach with no external dependencies — the attacker uses functionality already present in Windows rather than staging a third-party archiving binary.

PowerShell `Compress-Archive` is documented in red team tradecraft and has appeared in ransomware staging, data theft operations, and hands-on-keyboard intrusions. Its value to an attacker is simplicity: a single command recursively archives a target directory into a standard ZIP file that can be exfiltrated over any channel.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-17 17:33:23–17:33:28 UTC) and contains 1,310 PowerShell events, 4 Security events, and 40 Sysmon events across three log sources.

The attack command is captured in Security EID 4688:
```
"powershell.exe" & {dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\T1560-data-ps.zip}
```

And the cleanup command:
```
"powershell.exe" & {Remove-Item -path $env:USERPROFILE\T1560-data-ps.zip -ErrorAction Ignore}
```

Security EID 4688 also records the ART preflight `whoami.exe` check, giving 4 process creation events total. All four run as `NT AUTHORITY\SYSTEM`.

Sysmon EID 1 captures four process creation events with full hashes and parent-child relationships:
- `whoami.exe` (SHA256: `574BC2A2995FE2B1F732CCD39F2D99460ACE980AF29EFDF1EB0D3E888BE7D6F0`) spawned from `powershell.exe`
- The archiving `powershell.exe` (SHA256: `3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`) with full `dir $env:USERPROFILE -Recurse | Compress-Archive` command line
- A second `whoami.exe` run after the archive completes
- The cleanup `powershell.exe`

Sysmon EID 7 contributes 25 ImageLoad events documenting the DLL load chain for both PowerShell instances. Sysmon EID 10 (ProcessAccess) records 4 events where the test framework PowerShell accesses child processes — standard output-capture behavior. Sysmon EID 11 records 4 FileCreate events including the PowerShell startup profile data file. Sysmon EID 17 records 3 named pipe creation events (`\PSHost.*` pipes) for the PowerShell instances.

The PowerShell events break down to 1,188 EID 4103 (module logging) and 121 EID 4104 (script block logging). The high module logging count reflects `Compress-Archive`'s recursive traversal of `$env:USERPROFILE` — each file operation through the pipeline generates module logging events as PowerShell processes the stream of FileInfo objects. The 1 EID 4100 event records an error condition from the test framework wrapper.

The `Set-ExecutionPolicy Bypass -Scope Process -Force` scriptblock appears in 4104, along with `$ErrorActionPreference = 'Continue'` — standard ART test framework preamble.

## What This Dataset Does Not Contain

No network events appear. The test creates a local ZIP archive but makes no attempt to transmit it. No Sysmon EID 3 (NetworkConnect) or EID 22 (DNSQuery) events are present. The staging phase is captured but not the exfiltration phase.

No file content is logged. The ZIP archive at `$env:USERPROFILE\T1560-data-ps.zip` is created, but its contents — files from the SYSTEM user profile — are not recorded in any event. Object access auditing (EID 4663) is not configured, so individual file reads are invisible.

No Security log events beyond EID 4688 process creation. The defended variant produced 10 Security events including 4688/4689/4703 entries for the full process lifecycle. The undefended dataset has only 4 EID 4688 events — no process exit (4689) or token adjustment (4703) events were captured, suggesting the Security channel collection window closed before those events fired, or the collection configuration differs slightly.

No Sysmon EID 11 FileCreate for the ZIP file itself. The archive destination (`$env:USERPROFILE\T1560-data-ps.zip`) is not visible in file creation events — Sysmon's FileCreate filter did not match the `.zip` extension in this configuration.

## Assessment

This dataset captures a successful execution of the archiving technique. Unlike the defended variant — where Defender would have generated additional telemetry reacting to the compression activity — the undefended run is leaner: 1,354 total events versus 4,351 in the defended run. The dramatic reduction comes almost entirely from PowerShell module logging: the defended variant produced 4,304 PS events while this dataset contains 1,310.

The core detection evidence is equivalent between the two variants: Security EID 4688 and Sysmon EID 1 both capture the full `Compress-Archive` command line with environment variable expansion. The command line itself is the primary artifact regardless of whether Defender is active.

The high PowerShell module logging volume (1,188 EID 4103 events) is not itself suspicious — it reflects the legitimate operation of `Compress-Archive`. These events document each PowerShell command invoked during the recursive traversal, providing a detailed forensic record of the operation even though no individual event is a standalone indicator.

## Detection Opportunities Present in This Data

**Security EID 4688 command line**: `dir $env:USERPROFILE -Recurse | Compress-Archive -DestinationPath $env:USERPROFILE\T1560-data-ps.zip` from a SYSTEM-context PowerShell process. Recursive directory enumeration piped directly to `Compress-Archive` with a destination in the user profile is uncommon in normal operations, particularly when run as SYSTEM.

**Sysmon EID 1 for the archiving `powershell.exe`**: The process carries `RuleName: technique_id=T1059.001,technique_name=PowerShell` from the sysmon-modular rule set. The parent is the ART test framework PowerShell, creating a PowerShell-spawns-PowerShell pattern visible in the `ParentCommandLine` field.

**Sysmon EID 1 hash values**: The `powershell.exe` binary hash `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8` is captured. Any enterprise baseline that tracks known-good PowerShell binary hashes can validate or flag this.

**Cleanup `Remove-Item` command**: The ART cleanup command `Remove-Item -path $env:USERPROFILE\T1560-data-ps.zip -ErrorAction Ignore` is also captured in Security 4688. In a real intrusion, the immediate deletion of a created archive suggests the attacker knows they are being monitored or is covering traces after exfiltration.
