# T1547.001-4: Registry Run Keys / Startup Folder — Suspicious VBS File Run from Startup Folder

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through Windows startup folders in addition to registry run keys. The per-user startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) and the all-users startup folder (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`) cause any script or executable placed in them to run automatically at each user logon. Placing a VBScript (`.vbs`) file in a startup folder is a low-sophistication but reliable persistence mechanism, and the Windows Script Host (`wscript.exe` or `cscript.exe`) will execute it automatically at logon.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that copies `vbsstartup.vbs` from the ART atomics directory to both the per-user and all-users startup folders, then immediately executes the script using `cscript.exe` to simulate what would happen at the next logon.

**Sysmon (39 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). A child `powershell.exe` spawned to run the test body, with command line referencing `Copy-Item ... vbsstartup.vbs ... Startup`. `cscript.exe` spawned by the test PowerShell with command line: `"C:\Windows\system32\cscript.exe" "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"`. Also a `SearchProtocolHost.exe` process from the Windows Search indexer reacting to the new file.
- EID 7 (Image Load): DLL loads for both PowerShell processes (standard .NET runtime) and for `cscript.exe`. No suspicious DLLs.
- EID 10 (Process Access): PowerShell accessing `whoami.exe`.
- EID 11 (File Create): PowerShell profile data file. The `.vbs` file creation in the startup folder should be visible here but is not shown because the Sysmon include-mode filter does not match startup folder paths by default — see below.
- EID 17 (Pipe Create): Named pipe from PowerShell.

**Security (16 events):**
- EID 4688/4689: Process creates and exits for both PowerShell instances, `whoami.exe`, `cscript.exe`, a WMI provider host (`WmiPrvSE.exe` — unrelated background activity), and `SearchProtocolHost.exe`. The 4688 event for `cscript.exe` records the full command line including the startup folder path.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (37 events):**
- EID 4104 (Script Block Logging): The test scriptblock is captured in full: `Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\vbsstartup.vbs" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"` followed by a copy to the all-users StartUp folder, then `cscript.exe` invocation. The outer wrapper and inner body are each logged as separate scriptblocks.
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- Remainder are PowerShell runtime boilerplate scriptblocks.

## What This Dataset Does Not Contain

- No Sysmon EID 11 (File Create) event records the actual `.vbs` file being written to the startup folder. The sysmon-modular configuration's include-mode filtering for `FileCreate` does not target startup folder paths, so the file drop is not captured by Sysmon. The Security log also does not record it because object access auditing is disabled.
- No Sysmon EID 13 (Registry Value Set) events appear — this test uses the filesystem startup folder, not registry run keys, so no registry modification occurs.
- The content of `vbsstartup.vbs` is not visible in any log. The script was copied from the ART atomics directory; its behavior at execution is not recorded because only its invocation via `cscript.exe` is captured, not its output or child processes.
- There are no network connection events in this dataset.

## Assessment

The test completed successfully. The primary detection surface is the `cscript.exe` command line recorded in both Sysmon EID 1 and Security EID 4688, which shows `cscript.exe` executing a `.vbs` file located in the user's startup folder. The PowerShell EID 4104 scriptblock also captures the `Copy-Item` calls that place the file into both startup folder locations. Windows Defender did not block either the file copy or the `cscript.exe` execution.

Notably, the file creation event for the `.vbs` landing in the startup folder is absent from Sysmon. Defenders relying solely on Sysmon EID 11 to detect startup folder file drops will miss this unless their configuration explicitly includes startup folder path patterns.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `cscript.exe` or `wscript.exe` executing a file whose path includes `\Startup\` or `\StartUp\`. The command line explicitly names the startup folder path.
- **Security EID 4688**: Same `cscript.exe` process creation with startup folder path in command line, captured independently of Sysmon.
- **PowerShell EID 4104**: `Copy-Item` scriptblock referencing destination paths that match startup folder locations (`$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`).
- **Pattern**: Script interpreter (`cscript.exe`, `wscript.exe`) with a startup folder path in the command line is a high-confidence persistence indicator.
- **Gap to note**: File creation events for the `.vbs` drop are not present in this dataset due to Sysmon include-mode filtering. File integrity monitoring or Security log object access auditing would be needed to capture the file write itself.
