# T1547.001-5: Registry Run Keys / Startup Folder — Suspicious JSE File Run from Startup Folder

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through Windows startup folders as well as registry run keys. A `.jse` file is a JScript Encoded script — a format that obfuscates JScript source code using a simple XOR-based encoding scheme. Windows Script Host will execute `.jse` files using the JScript engine when invoked with `cscript.exe /E:Jscript` or simply by double-clicking. Placing an encoded JScript file in the startup folder is a low-profile persistence approach that avoids storing plaintext script content on disk.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that copies `jsestartup.jse` to both the per-user and all-users startup folders, then immediately executes it using `cscript.exe /E:Jscript` to simulate the next logon.

**Sysmon (46 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). A child `powershell.exe` with command line referencing `Copy-Item ... jsestartup.jse ... Startup`. `cscript.exe` spawned with command line: `"C:\Windows\system32\cscript.exe" /E:Jscript "C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"`. The `/E:Jscript` flag is used because the `.jse` extension requires specifying the engine explicitly.
- EID 7 (Image Load): DLL loads for PowerShell processes and `cscript.exe` — standard runtime behavior. Multiple T1055/T1574.002-tagged loads for the PowerShell .NET runtime.
- EID 10 (Process Access): PowerShell accessing `whoami.exe` with `0x1FFFFF`.
- EID 11 (File Create): PowerShell startup profile data file only. The `.jse` startup folder file creation is not captured (see below).
- EID 17 (Pipe Create): Named pipe from PowerShell.

**Security (14 events):**
- EID 4688/4689: Process creates and exits for both PowerShell instances, `whoami.exe`, and `cscript.exe`. The 4688 event for `cscript.exe` records the full command line including the startup folder path and the `/E:Jscript` flag.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (37 events):**
- EID 4104 (Script Block Logging): The test scriptblock is captured: `Copy-Item "C:\AtomicRedTeam\atomics\T1547.001\src\jsestartup.jse" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"`, followed by the all-users StartUp copy, then the `cscript.exe /E:Jscript` invocation. Both the wrapped (`& {...}`) and unwrapped forms appear as separate 4104 events.
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- Remainder are PowerShell runtime error-handler boilerplate scriptblocks.

## What This Dataset Does Not Contain

- No Sysmon EID 11 (File Create) captures the `.jse` file being written to the startup folder. The sysmon-modular include-mode configuration does not match startup folder paths in its `FileCreate` rules, so the file drop goes unrecorded by Sysmon.
- No Sysmon EID 13 (Registry Value Set) events are present — this test uses the filesystem startup folder, not registry keys.
- The content of `jsestartup.jse` is not visible. Being a JSE encoded file, its contents would be obfuscated even if captured; neither Sysmon nor the Security log record script content for non-PowerShell interpreters.
- No network connection events appear in this dataset.
- No AMSI scan events for the JSE content are present because AMSI does not intercept Windows Script Host `.jse` execution in the same way it intercepts PowerShell.

## Assessment

The test completed successfully. The `cscript.exe /E:Jscript` invocation with the startup folder path is captured in Sysmon EID 1 and Security EID 4688, providing a reliable detection point. The `/E:Jscript` flag alongside a startup folder file path is a distinctive combination.

Compared to the VBS variant (test 4), this test produces an almost identical telemetry pattern — the only differences are the file extension (`.jse` vs `.vbs`) and the explicit engine flag (`/E:Jscript`). The absence of the file creation event in Sysmon applies equally to both tests. Windows Defender did not block the file copy or the `cscript.exe` execution of the encoded JScript.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `cscript.exe` with `/E:Jscript` executing a file whose path includes `\Startup\` or `\StartUp\`. The combination of the explicit engine specification and startup folder path is notable.
- **Security EID 4688**: Same `cscript.exe` process creation event independently recording the full command line with startup folder path.
- **PowerShell EID 4104**: `Copy-Item` scriptblock with destination paths matching startup folder locations. The `.jse` extension in a startup folder copy operation is a meaningful indicator.
- **Pattern**: `cscript.exe /E:Jscript` invocations in general warrant scrutiny; the `.jse` extension is rare in legitimate enterprise software deployment.
- **Gap to note**: File creation events for the `.jse` drop in the startup folder are absent from this dataset due to Sysmon's include-mode filtering. Detection of the file write itself requires either a broader Sysmon `FileCreate` configuration or endpoint protection file monitoring.
