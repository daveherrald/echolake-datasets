# T1547.001-6: Registry Run Keys / Startup Folder — Suspicious BAT File Run from Startup Folder

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through Windows startup folders as well as registry run keys. Placing a batch script (`.bat`) in the per-user or all-users Windows startup folder causes it to execute at each logon, interpreted by `cmd.exe`. Batch files are one of the oldest and simplest persistence mechanisms on Windows — they require no special privileges to place in the per-user folder and leave no registry artifacts. Despite being low-sophistication, they remain in active use by adversaries because of their broad compatibility and simple execution model.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that copies `batstartup.bat` to both the per-user and all-users startup folders, then immediately executes the batch file using `cmd.exe` to simulate what would happen at the next logon.

**Sysmon (41 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). A child `powershell.exe` with command line showing `Copy-Item ... batstartup.bat ... Startup`. `cmd.exe` spawned by PowerShell with the full startup folder path: `C:\Windows\system32\cmd.exe /c "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"`.
- EID 7 (Image Load): DLL loads for both PowerShell processes — standard .NET runtime startup behavior, tagged with T1055 and T1574.002 rule names.
- EID 10 (Process Access): PowerShell accessing `whoami.exe` with `0x1FFFFF`.
- EID 11 (File Create): PowerShell startup profile data file only. The `.bat` file creation in the startup folder is not captured (see below).
- EID 17 (Pipe Create): Named pipe from PowerShell.

**Security (16 events):**
- EID 4688/4689: Process creates and exits for both PowerShell instances, `whoami.exe`, and `cmd.exe`. The 4688 event for `cmd.exe` records the full command line: `C:\Windows\system32\cmd.exe /c "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"`. This is the direct execution simulation.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (37 events):**
- EID 4104 (Script Block Logging): Two substantive scriptblocks logged. The outer wrapper: `& {Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\batstartup.bat" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"; Copy-Item ... "C:\ProgramData\...\StartUp\batstartup.bat"; Start-Process ...}`. The inner body is also captured separately.
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- Remainder are PowerShell runtime error-handler boilerplate scriptblocks.

## What This Dataset Does Not Contain

- No Sysmon EID 11 (File Create) captures the `.bat` file being written to the startup folder. The sysmon-modular include-mode configuration's `FileCreate` rules do not match startup folder paths, so the file drop is not recorded.
- No Sysmon EID 13 (Registry Value Set) events — this test uses the filesystem startup folder, not registry keys.
- The content of `batstartup.bat` is not visible in the logs. Batch script content is never captured by script block logging (which is PowerShell-specific) or AMSI.
- `cmd.exe` spawned from the startup folder execution does not produce any visible child process events — either the batch file's commands exit quickly or the batch content itself is trivial (likely a no-op or simple echo used for ART test purposes).
- No network connection events appear.

## Assessment

The test completed successfully. The `cmd.exe` invocation with the startup folder path is captured in both Sysmon EID 1 and Security EID 4688, providing a reliable detection anchor. The PowerShell 4104 scriptblock captures the `Copy-Item` calls that drop the file into both startup locations.

This test produces the simplest telemetry of the startup-folder variant tests (compared to the VBS and JSE tests): `cmd.exe` is less distinctive than `cscript.exe` because `cmd.exe` has many legitimate uses. However, the combination of `cmd.exe` executing a file whose path resolves to a startup folder location is a strong indicator. Windows Defender did not block any part of this test.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `cmd.exe` with a command line that contains a startup folder path (any variant of `\Programs\Startup\` in the argument) is a reliable detection pattern for this class of persistence.
- **Security EID 4688**: Same `cmd.exe` process creation event with startup folder path in command line, recorded independently of Sysmon.
- **PowerShell EID 4104**: `Copy-Item` scriptblock with destination paths matching startup folder locations (`$env:APPDATA\...\Startup` or `C:\ProgramData\...\StartUp`). The `.bat` extension in a startup folder copy is a meaningful indicator.
- **Pattern**: Any file creation or process execution referencing startup folder paths by non-system processes should be investigated. The per-user path (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) and all-users path (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`) are both targets.
- **Gap to note**: The file write itself to the startup folder is not captured by Sysmon in this configuration. Broader file monitoring or endpoint protection coverage of startup folder paths is needed to detect the placement action separately from the execution action.
