# T1547.001-6: Registry Run Keys / Startup Folder — Suspicious BAT File Run from Startup Folder

## Technique Context

T1547.001 covers persistence through Windows startup folders as well as registry run keys. This test places a batch script (`.bat`) in both the per-user and all-users startup folders, causing it to execute at each user logon via `cmd.exe`. Batch files are among the oldest and most broadly compatible persistence mechanisms on Windows — they require no special privileges to place in the per-user startup folder, produce no registry artifacts, and run in the user's session context without requiring any scripting runtime beyond `cmd.exe` itself, which is present on every Windows system.

Despite being low-sophistication, batch file startup persistence remains in active use in real-world campaigns because of its reliability and simplicity. The startup folder mechanism predates run keys and continues to work identically across Windows versions. Unlike `.vbs` (T1547.001-4) or `.jse` (T1547.001-5) files, batch files execute in the `cmd.exe` console window by default and can be identified by extension alone.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-6` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A child `powershell.exe` copies `batstartup.bat` from `C:\AtomicRedTeam\atomics\T1547.001\src\` to both startup folders, then immediately executes it via `cmd.exe` (via `Start-Process`) to simulate logon-time execution.

**Sysmon (29 events — EIDs 1, 7, 10, 11, 17):**

EID 1 (ProcessCreate) captures four processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `powershell.exe` (child, tagged T1059.001) with command line: `"powershell.exe" & {Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\batstartup.bat" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"; Copy-Item ... "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"; Start-Process ...}` — the full file copy and execution setup
- `cmd.exe` (tagged T1059.003, Windows Command Shell) with command line: `C:\Windows\system32\cmd.exe /c ""C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat" "` — the batch file executed from the all-users startup path
- A second `whoami.exe` at cleanup

The `cmd.exe` execution of `batstartup.bat` is captured in Sysmon EID 1 with the full path to the startup folder location, including the double-quoting convention that Windows uses when executing batch files with spaces in the path.

EID 11 (FileCreate) shows `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — the PowerShell startup profile cache. The `.bat` file written to the startup folder is not captured (see below).

EID 7 (ImageLoad) accounts for 18 events covering .NET runtime DLL loads for both PowerShell instances. EID 10 (ProcessAccess) and EID 17 (PipeCreate) are standard test framework artifacts.

**Security (4 events — EID 4688):**

Four EID 4688 process creation events:
- Outer `powershell.exe`
- Inner `powershell.exe` with the `Copy-Item ... Start-Process` command targeting both startup folder paths
- `cmd.exe` executing the batch file: `C:\Windows\system32\cmd.exe /c ""C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat" "` — the all-users startup folder execution is captured with the full path
- One additional process at cleanup

All processes ran as `NT AUTHORITY\SYSTEM`.

**PowerShell (113 events — EIDs 4100, 4102, 4103, 4104):**

This dataset includes EID 4100 (two events) and EID 4102 (one event) alongside the standard boilerplate EID 4104 events, indicating runtime events occurred during execution. The substantive EID 4104 scriptblocks include the outer wrapper with `Copy-Item` targeting both startup folders and the `Start-Process` call, plus the cleanup `Remove-Item` operations for both startup folder copies.

The EID 4104 batch startup test scriptblock: `& {Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\batstartup.bat" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"; Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\batstartup.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"; Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"}` is captured in full.

Compared to the defended variant (41 Sysmon, 16 Security, 37 PowerShell), the undefended run produces fewer events (29 Sysmon, 4 Security, 113 PowerShell). The lower Sysmon and Security counts may reflect a narrower collection window or fewer background processes active during the test.

## What This Dataset Does Not Contain

- No Sysmon EID 11 (FileCreate) captures the `.bat` file being written to the startup folder. This is the same sysmon-modular `FileCreate` monitoring gap as in T1547.001-4 and T1547.001-5 — startup folder paths are not matched by the include-mode filter.
- The content of `batstartup.bat` is not logged. Batch script content is not captured by PowerShell script block logging or any other standard Windows telemetry source without file auditing.
- Only the all-users startup folder execution (`\ProgramData\...`) is captured in Sysmon EID 1 and Security EID 4688. The per-user startup folder execution (via `Start-Process`) may be in the full dataset.
- No actual user logon-time execution occurs — the batch file is run directly by the test framework.

## Assessment

This dataset provides the cleanest execution chain of the three startup folder script variants in this batch (`.vbs`, `.jse`, `.bat`). The `cmd.exe` execution of the batch file is unambiguous in both Sysmon EID 1 and Security EID 4688, with the full startup folder path visible. The PowerShell `Copy-Item` command line in EID 4104 and EID 4688 documents the file placement.

The consistent absence of Sysmon EID 11 for startup folder file drops across T1547.001-4, -5, and -6 establishes a pattern: sysmon-modular does not monitor startup folder paths for file creation, and all three startup folder persistence variants share this monitoring gap. This is important for dataset users to understand when designing detection coverage.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 1** for `cmd.exe` with a command line argument pointing to a startup folder path (matching `\Microsoft\Windows\Start Menu\Programs\Startup\` or `\Microsoft\Windows\Start Menu\Programs\StartUp\`) containing a `.bat` extension — `cmd.exe` directly executing a batch file from the startup folder is captured here as tagged T1059.003.

- **Security EID 4688** recording `cmd.exe` with a startup folder path in the command line — the full path including `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat` is in the command line field.

- **Security EID 4688** recording `powershell.exe` with a command line containing `Copy-Item` combined with `\Microsoft\Windows\Start Menu\Programs\Startup\` and a `.bat`, `.vbs`, or `.jse` extension — the file placement is directly observable in the PowerShell command line even though Sysmon EID 11 does not capture it.

- **`Start-Process` in a PowerShell command line targeting a startup folder path**: `Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"` is captured in EID 4104 and EID 4688, indicating automated execution of a newly placed startup folder script.

- **Cross-variant detection**: a single rule matching `cmd.exe` or any scripting host (`cscript.exe`, `wscript.exe`) with a startup folder path in the command line, or a `Copy-Item`/file write targeting a startup folder path from an elevated or SYSTEM-level process, covers T1547.001-4, -5, and -6 with a single logical condition.
