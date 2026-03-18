# T1547.001-5: Registry Run Keys / Startup Folder — Suspicious JSE File Run from Startup Folder

## Technique Context

T1547.001 covers persistence through Windows startup folders as well as registry run keys. This test uses a `.jse` file — a JScript Encoded script — placed in both the per-user and all-users startup folders. JScript Encoded files use a simple XOR-based encoding scheme (`screnc.exe` or compatible tools) to obfuscate JScript source, producing a file that Windows Script Host executes via the JScript engine when called with `cscript.exe /E:Jscript` or when the `.jse` extension is associated with the JScript engine.

The `.jse` format is used to avoid storing plaintext script content on disk, providing a lightweight layer of obfuscation while still achieving reliable execution. Unlike `.vbs` files (T1547.001-4), `.jse` files require the `/E:Jscript` flag when invoked with `cscript.exe`, because the encoding removes the standard JScript file signature that Windows uses for engine detection. This is a minor operational difference that is nonetheless captured in the process command line and visible in telemetry.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-5` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A child `powershell.exe` copies `jsestartup.jse` from `C:\AtomicRedTeam\atomics\T1547.001\src\` to both startup folders, then immediately executes it via `cscript.exe /E:Jscript` for both copies.

**Sysmon (35 events — EIDs 1, 7, 10, 11, 17):**

EID 1 (ProcessCreate) captures five processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `powershell.exe` (child, tagged T1059.001) with command line: `"powershell.exe" & {Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\jsestartup.jse" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"; Copy-Item ... "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"; cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"}`
- `cscript.exe` with command line: `"C:\Windows\system32\cscript.exe" /E:Jscript "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"` — the `/E:Jscript` flag is clearly visible, confirming the encoded JScript format
- A second `whoami.exe` at the start of cleanup
- Note: only 5 EID 1 events are in the sample set; the second `cscript.exe` execution (from the all-users folder) and the cleanup PowerShell may be in the full dataset given the total Sysmon count is 35

EID 11 (FileCreate) shows `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` being written — the PowerShell startup profile cache written during initialization. The `.jse` file written to the startup folder is not captured (see below).

EID 7 (ImageLoad) accounts for 21 events covering .NET runtime DLL loads for PowerShell and `cscript.exe`. EID 10 (ProcessAccess) and EID 17 (PipeCreate) are standard test framework artifacts.

**Security (5 events — EID 4688):**

Five EID 4688 process creation events are present:
- `whoami.exe` (identity check)
- Inner `powershell.exe` with the full `Copy-Item ... cscript.exe /E:Jscript` command
- `cscript.exe /E:Jscript "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"` — per-user startup path execution
- `cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"` — all-users startup path execution
- One additional process (outer PowerShell or cleanup)

The two `cscript.exe` entries each record the startup folder path and the `/E:Jscript` engine flag, providing clear evidence of encoded JScript execution from both startup locations.

**PowerShell (108 events — EIDs 4100, 4102, 4103, 4104):**

As with T1547.001-4, this dataset includes EID 4100 and EID 4102 events indicating a runtime event occurred during execution. The substantive EID 4104 scriptblocks capture the `Copy-Item ... jsestartup.jse` commands and the cleanup `Remove-Item` operations.

Compared to the defended variant (46 Sysmon, 14 Security, 37 PowerShell), the undefended run produces fewer Sysmon events (35 vs. 46) and similar Security and PowerShell counts. The lower Sysmon count in the undefended run likely reflects a slightly narrower collection window or fewer DLL loads during `cscript.exe` initialization.

## What This Dataset Does Not Contain

- No Sysmon EID 11 captures the `.jse` file being written to the startup folder. The sysmon-modular `FileCreate` include-mode rules do not match startup folder paths, so the file drop is invisible to Sysmon. This is the same gap as in T1547.001-4 (`.vbs`) and T1547.001-6 (`.bat`).
- The content of `jsestartup.jse` is not logged. The encoded JScript source is opaque to standard Windows logging.
- No actual user logon-time execution in a real session occurs — `cscript.exe` is invoked directly to simulate the logon trigger.
- No Windows Search indexer reaction is present in this dataset (unlike T1547.001-4), suggesting the Search service did not react to the `.jse` file within the collection window.

## Assessment

This dataset is structurally similar to T1547.001-4 (`.vbs` startup) but with the distinguishing `/E:Jscript` flag marking the encoded JScript format. The `cscript.exe /E:Jscript` invocation from a startup folder path is captured in both Sysmon EID 1 and Security EID 4688, providing clear and actionable telemetry.

The file drop itself (the `.jse` file written to the startup folder) is again absent from Sysmon EID 11, consistent with the sysmon-modular `FileCreate` monitoring gap for startup folder paths. Process creation auditing is the primary detection source for this technique variant.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 1** for `cscript.exe` with `/E:Jscript` in the command line combined with a startup folder path argument — the `/E:Jscript` flag is particularly notable because legitimate JScript files (`.js`) do not require it; its presence indicates either an encoded `.jse` file or an attempt to force JScript interpretation of an arbitrary file.

- **Security EID 4688** recording `cscript.exe` with both `/E:Jscript` and a path containing `\Microsoft\Windows\Start Menu\Programs\Startup\` — two high-signal indicators in a single event.

- **Security EID 4688** recording `powershell.exe` with a command line containing `Copy-Item` targeting a startup folder path combined with a `.jse` extension — the file copy is directly observable in the PowerShell command line even without Sysmon `FileCreate` coverage.

- **The `/E:Jscript` flag as a standalone indicator**: any `cscript.exe` or `wscript.exe` invocation using `/E:Jscript` (rather than relying on `.js` extension detection) is potentially executing an encoded script. Combined with a startup folder path, this is a high-confidence indicator.

- **Startup folder path in any process command line**: `\Microsoft\Windows\Start Menu\Programs\Startup\` or `\Microsoft\Windows\Start Menu\Programs\StartUp\` appearing as an argument to a scripting host (`cscript.exe`, `wscript.exe`, `mshta.exe`) or a copy operation targeting these paths from a SYSTEM-level process.
