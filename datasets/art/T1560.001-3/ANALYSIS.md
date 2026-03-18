# T1560.001-3: Archive via Utility — Compress Data and lock with password for Exfiltration with winzip

## Technique Context

T1560.001 (Archive via Utility) covers adversary use of compression and archival tools to stage collected data before exfiltration. This test exercises WinZip as the archiving tool, using its command-line interface with a password switch. Like WinRAR, WinZip is widely deployed in enterprise environments and its command-line utility (`winzip64.exe`) is frequently overlooked by security controls focused on native Windows tools.

## What This Dataset Contains

The dataset captures 71 events across Sysmon, Security, and PowerShell logs collected during a 5-second window on 2026-03-14 at 01:19 UTC.

The core technique activity is documented in Security EID 4688. The archiving command was launched by PowerShell and includes the WinZip invocation with a password:

```
"cmd.exe" /c path=%path%;"C:\Program Files (x86)\winzip" & mkdir .\tmp\victim-files & cd .\tmp\victim-files & echo "This file will be encrypted" > .\encrypted_file.txt & "%ProgramFiles%\WinZip\winzip64.exe" -min -a -s"hello" archive.zip * & dir
```

Key observations from the data:

- Security EID 4688 records `cmd.exe` with the full WinZip command line including the `-s"hello"` password switch, spawned by `powershell.exe` as NT AUTHORITY\SYSTEM.
- Security EID 4688 also records `whoami.exe` as a pre-execution discovery step by the ART test framework.
- Sysmon EID 1 captures `whoami.exe` (RuleName: `technique_id=T1033`) and `cmd.exe` (RuleName: `technique_id=T1083`), matching the same parent-child relationship from PowerShell.
- Sysmon EID 11 records creation of `C:\Windows\Temp\tmp\victim-files\encrypted_file.txt` by `cmd.exe`.
- Sysmon EID 7 (ImageLoad) fires multiple times for the PowerShell process loading its standard DLL chain, annotated with heuristic rule names (T1055, T1574.002). These reflect Sysmon's rule matching on the loaded library names, not actual injection activity.
- Sysmon EID 10 (ProcessAccess) from PowerShell targeting `whoami.exe` with full access (0x1FFFFF) is an ART test framework artifact from output capture.
- Sysmon EID 17 records the PowerShell named pipe (`\PSHost.*`) creation.
- PowerShell EID 4104 is dominated by ART internal error-handling scriptblocks and EID 4103 by the `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` invocation. Neither contains technique-specific content.

The path manipulation at the start of the command (`path=%path%;"C:\Program Files (x86)\winzip"`) is a characteristic WinZip invocation pattern, adding the WinZip directory to PATH before use.

## What This Dataset Does Not Contain (and Why)

**No winzip64.exe process creation in Sysmon (EID 1).** The sysmon-modular include-mode configuration does not match `winzip64.exe`, so the archiver process is invisible to Sysmon. Security EID 4688 with command-line logging captures the full invocation.

**No archive output file in Sysmon EID 11.** The `archive.zip` output is not recorded as a Sysmon FileCreate event.

**No network activity.** This test stages data without exfiltrating it. No EID 3 or DNS events are present.

**No WinZip installation evidence.** The test assumes WinZip is installed. If absent, execution silently fails after the file creation step.

## Assessment

This dataset is structurally identical to T1560.001-2 (WinRAR) except for the archiving binary. The Security EID 4688 command line is the highest-fidelity indicator, clearly showing `winzip64.exe` with a `-s"hello"` password argument. The Sysmon data provides process lineage and the victim file staging artifact but does not capture the archiver binary itself. The PowerShell log contains no technique-relevant content beyond ART boilerplate. The dataset is a realistic representation of WinZip-based staging as it appears in an environment with Sysmon include-mode filtering and full Security audit policy.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` command line containing `winzip64.exe` with `-s"` password flag, spawned from `powershell.exe` as SYSTEM.
- **Security EID 4688**: PATH manipulation adding WinZip directory before invocation — `path=%path%;"C:\Program Files (x86)\winzip"` — is a recognizable WinZip CLI pattern.
- **Sysmon EID 11**: File creation in staging path `\victim-files\` under a temp directory.
- **Sysmon EID 1**: `whoami.exe` as SYSTEM with `powershell.exe` parent, consistent with post-exploitation activity before data staging.
- **Behavioral correlation**: `cmd.exe` spawning file creation followed by an archive utility with a password switch, all within seconds under SYSTEM, is a high-fidelity staging indicator regardless of the specific archiver used.
