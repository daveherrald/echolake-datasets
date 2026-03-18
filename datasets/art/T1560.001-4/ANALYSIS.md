# T1560.001-4: Archive via Utility — Compress Data and lock with password for Exfiltration with 7zip

## Technique Context

T1560.001 (Archive via Utility) covers adversary use of compression and archival tools to stage collected data before exfiltration. This test exercises 7-Zip via its command-line interface (`7z.exe`). 7-Zip is particularly notable from a security perspective because it is free, open-source, widely installed across enterprise environments, and supports AES-256 encryption on archives. It is frequently seen in data-theft intrusions targeting both Windows workstations and servers.

## What This Dataset Contains

The dataset captures 80 events across Sysmon, Security, and PowerShell logs collected during a 6-second window on 2026-03-14 at 01:19–01:20 UTC.

The archiving command is captured in Security EID 4688 and Sysmon EID 1:

```
"cmd.exe" /c mkdir C:\AtomicRedTeam\atomics\T1560.001\victim-files & cd C:\AtomicRedTeam\atomics\T1560.001\victim-files & echo "This file will be encrypted" > .\encrypted_file.txt & "%ProgramFiles%\7-zip\7z.exe" u archive.7z *txt -pblue & dir
```

Key observations from the data:

- Security EID 4688 records the full `cmd.exe` command line with `7z.exe u archive.7z *txt -pblue` — the `u` (update) command and `-p` password flag are both clearly visible. The staging path differs from tests 2 and 3: files are written to `C:\AtomicRedTeam\atomics\T1560.001\victim-files\`.
- Sysmon EID 1 fires for both `whoami.exe` (T1033 rule) and `cmd.exe` (T1083 rule), with full command lines and process hashes (SHA1, MD5, SHA256, IMPHASH).
- Sysmon EID 1 for `cmd.exe` shows the `ParentCommandLine: powershell.exe` and `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` confirming execution origin.
- Sysmon EID 11 records the victim file creation at `C:\Windows\Temp\tmp\victim-files\encrypted_file.txt` (pre-staging) and a PowerShell profile data file write.
- Sysmon EID 7 (ImageLoad) fires for the PowerShell DLL load chain (T1055, T1059.001, T1574.002 rule annotations — standard PowerShell startup artifacts).
- Sysmon EID 10 (ProcessAccess) with `GrantedAccess: 0x1FFFFF` from PowerShell to `whoami.exe` is an ART output-capture artifact.
- PowerShell EID 4104 contains the ART scriptblock: `& {... & echo ... & "%%ProgramFiles%%\7-zip\7z.exe" u archive.7z *txt -pblue ...}` — the full archive command appears in the scriptblock log after percent-encoding expansion.
- PowerShell EID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — ART test framework boilerplate.

This dataset has 36 Sysmon events compared to 27 in the WinRAR and WinZip tests, reflecting additional file creation events at the ART atomics staging path.

## What This Dataset Does Not Contain (and Why)

**No 7z.exe process creation in Sysmon (EID 1).** The sysmon-modular include-mode configuration does not include a rule matching `7z.exe`. Security EID 4688 captures the parent `cmd.exe` with the full 7-Zip command line but the `7z.exe` process itself does not appear in Sysmon.

**No archive output file in Sysmon EID 11.** The resulting `archive.7z` is not captured as a FileCreate event.

**No network activity.** Data is staged but not exfiltrated. No EID 3 or DNS events.

**No evidence of archive encryption being verified.** The password `-pblue` is present in the command line but there is no telemetry confirming the archive was successfully created and encrypted.

## Assessment

This dataset captures a 7-Zip password-protected archive operation with excellent fidelity in the Security log and partial coverage in Sysmon. The `-pblue` password flag is visible in both Security EID 4688 (via the `cmd.exe` command line) and the PowerShell EID 4104 scriptblock log, providing two independent log sources for the same indicator. The 7z.exe process itself is invisible to Sysmon due to include-mode filtering, but the behavioral chain — PowerShell spawning cmd.exe with an archive utility — is captured. The PowerShell module logging (EID 4103) also records the Set-ExecutionPolicy bypass as a consistent ART test framework artifact.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` command line containing `7z.exe` with `-p` password flag, spawned from `powershell.exe` as SYSTEM.
- **PowerShell EID 4104**: Scriptblock containing `7z.exe` invocation with `-p` password argument — provides redundant detection via the PowerShell logging path.
- **Sysmon EID 1**: `cmd.exe` with `RuleName: technique_id=T1083` spawned by PowerShell as SYSTEM, immediately after `whoami.exe` — pre-staging reconnaissance footprint.
- **Sysmon EID 11**: File creation in an ART atomics staging path (`C:\AtomicRedTeam\atomics\T1560.001\victim-files\`), which in a production environment would indicate a specific tooling artifact.
- **Behavioral correlation**: Command sequence `whoami` → `mkdir` → file write → archiver with password flag, all within seconds under SYSTEM, is a robust staging indicator across archive utility variants.
