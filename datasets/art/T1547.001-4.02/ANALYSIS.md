# T1547.001-4: Registry Run Keys / Startup Folder — Suspicious VBS File Run from Startup Folder

## Technique Context

T1547.001 covers persistence through Windows startup folders as well as registry run keys. Both the per-user startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) and the all-users startup folder (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`) cause any script or executable placed in them to run automatically at each user logon — the per-user folder fires for that user, the all-users folder fires for every user.

Placing a VBScript (`.vbs`) file in a startup folder is a low-sophistication but reliable persistence mechanism. Windows Script Host (`wscript.exe` or `cscript.exe`) will execute it automatically at logon without requiring registry modifications. VBScript files can call arbitrary Windows COM objects, launch processes, download content, and exfiltrate data — they are general-purpose execution wrappers with extensive Windows API access. The `.vbs` extension is associated with both `wscript.exe` and `cscript.exe`, and the script runs in the user's session context.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-4` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A child `powershell.exe` copies `vbsstartup.vbs` from `C:\AtomicRedTeam\atomics\T1547.001\src\` to both startup folders, then immediately executes it via `cscript.exe` to simulate logon-time execution.

**Sysmon (46 events — EIDs 1, 7, 10, 11, 17):**

EID 1 (ProcessCreate) captures six processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `powershell.exe` (child, tagged T1059.001) with command line showing: `"powershell.exe" & {Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\vbsstartup.vbs" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"; Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\vbsstartup.vbs" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"; cscript.exe "...Startup\vbsstartup.vbs"}`
- `cscript.exe` with command line: `"C:\Windows\system32\cscript.exe" "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"` — direct execution of the VBS from the per-user startup path
- `SearchProtocolHost.exe` — the Windows Search indexer reacting to the new `.vbs` file in the startup folder
- A second `cscript.exe` executing from the all-users folder: `"C:\Windows\system32\cscript.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"`
- `powershell.exe` for cleanup

The `SearchProtocolHost.exe` process (full command line: `"C:\Windows\System32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe7_ ...`) appearing after the VBS file drop is a characteristic artifact of placing a new file in an indexed location — the Windows Search indexer picks up the new file and spawns a protocol host to catalog it. This background process is expected, real-world behavior.

EID 7 (ImageLoad) accounts for 30 events covering .NET runtime DLL loads for both PowerShell instances and for `cscript.exe`. EID 10 (ProcessAccess) and EID 17 (PipeCreate) are standard test framework artifacts. EID 11 (FileCreate) records only the PowerShell startup profile data file — the `.vbs` file written to the startup folder is not captured because the sysmon-modular include-mode `FileCreate` filter does not match startup folder paths.

**Security (7 events — EID 4688):**

Seven EID 4688 process creation events provide full command line visibility:
- Outer `powershell.exe`
- `whoami.exe`
- Inner `powershell.exe` with the full `Copy-Item ... cscript.exe` command
- `cscript.exe` executing `vbsstartup.vbs` from the per-user startup path
- `SearchProtocolHost.exe` (background indexer, full arguments captured)
- A second `cscript.exe` executing `vbsstartup.vbs` from the all-users startup path
- Cleanup `powershell.exe` running `Remove-Item` to clean both startup folder copies

The `cscript.exe` EID 4688 events are the primary forensic artifact: they record the startup folder path and `.vbs` filename for both execution instances.

**PowerShell (108 events — EIDs 4100, 4102, 4103, 4104):**

This dataset includes EID 4100 (PowerShell host error message) and EID 4102 (pipeline execution details) — the same as in T1547.001-14 — indicating a runtime event or error was logged during the test or cleanup execution. The substantive EID 4104 scriptblocks capture the `Copy-Item ... vbsstartup.vbs` commands and the cleanup `Remove-Item` operations.

Compared to the defended variant (39 Sysmon, 16 Security, 37 PowerShell), the undefended run produces more events (46 Sysmon, 7 Security, 108 PowerShell). The higher Sysmon count and PowerShell count reflect additional module loading and script block events in the undefended environment.

## What This Dataset Does Not Contain

- No Sysmon EID 11 (FileCreate) captures the `.vbs` file being written to the startup folder. The sysmon-modular `FileCreate` rules use include-mode filters that do not match startup folder paths (`\Microsoft\Windows\Start Menu\Programs\Startup\`). The file drop is only observed through the EID 4688 PowerShell command line and the resulting `cscript.exe` execution.
- The content of `vbsstartup.vbs` is not logged. Script block logging captures the PowerShell wrapper but not the VBScript source.
- No actual logon-time execution in a real user session occurs — `cscript.exe` is invoked directly by the test framework to simulate what would happen at the next logon.

## Assessment

This dataset demonstrates startup folder persistence with the full execution chain: file drop (visible in PowerShell EID 4688 command line), immediate execution simulation (`cscript.exe` EID 4688 and Sysmon EID 1), and cleanup (`Remove-Item` in the cleanup PowerShell). The Windows Search indexer reaction (`SearchProtocolHost.exe`) is a real-world side effect that provides additional temporal correlation evidence.

The absence of Sysmon EID 11 for the startup folder file write is a notable gap that applies equally to the defended and undefended variants — it is a configuration property of sysmon-modular, not a Defender interaction.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 1** for `cscript.exe` or `wscript.exe` with a command line argument containing a path within `Microsoft\Windows\Start Menu\Programs\Startup` — executing a script from a startup folder path during a non-logon session (e.g., invoked by a SYSTEM-level process) is anomalous.

- **Security EID 4688** recording `cscript.exe` with a startup folder path in its command line, spawned by `powershell.exe` running as `NT AUTHORITY\SYSTEM` — the parent-child relationship (`powershell.exe` → `cscript.exe` executing a startup folder script) is suspicious.

- **Security EID 4688** recording `powershell.exe` with a command line containing `Copy-Item` targeting `\Microsoft\Windows\Start Menu\Programs\Startup\` combined with a `.vbs`, `.jse`, `.bat`, `.js`, or `.ps1` extension — the file copy to a startup folder is directly captured in the command line.

- **Sysmon EID 1** for `SearchProtocolHost.exe` spawned shortly after a `cscript.exe` execution from a startup folder path — the search indexer reaction is a corroborating side-effect indicator of a new file appearing in an indexed startup location.

- **Startup folder file audit** (not present in this dataset but feasible): adding a `FileCreate` rule matching `\Microsoft\Windows\Start Menu\Programs\Startup\` to the sysmon configuration would capture the `.vbs` file drop directly. This gap is identifiable from this dataset.
