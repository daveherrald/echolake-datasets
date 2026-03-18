# T1547.001-7: Registry Run Keys / Startup Folder — Add Executable Shortcut Link to User Startup Folder

## Technique Context

T1547.001 (Registry Run Keys / Startup Folder) covers persistence mechanisms that cause code to execute automatically at logon. The Startup folder variant places a shortcut (.lnk) file in the user's Startup folder, causing the linked executable to launch whenever that user logs in. This is one of the simplest and most accessible persistence methods on Windows — it requires no elevated privileges for the per-user path and leaves no registry modification, making it distinct from run key variants.

## What This Dataset Contains

The dataset captures a 5-second window on ACME-WS02 (Windows 11 Enterprise, domain-joined, SYSTEM context) around execution of the ART test that creates a `.lnk` shortcut pointing to `calc.exe` in the user Startup folder.

**PowerShell script block logging (4104) captures the exact test payload:**

```
$Target = "C:\Windows\System32\calc.exe"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
```

A 4103 module logging event records `CommandInvocation(New-Object)` with `ComObject=WScript.Shell`, the standard mechanism for creating shortcut files from PowerShell.

**Sysmon events include:**

- **Event ID 11 (FileCreate)** tagged `technique_id=T1187,technique_name=Forced Authentication` — the .lnk file creation in the Startup folder is flagged by the sysmon-modular config with this rule annotation (sysmon-modular associates .lnk files in Startup with potential forced-auth abuse as well as persistence).
- **Event ID 1 (ProcessCreate)** for `powershell.exe` tagged `technique_id=T1059.001`.
- Multiple **Event ID 7 (ImageLoad)** events for PowerShell DLL loads tagged with T1055 and T1574.002 — standard PowerShell process initialization artifacts.
- **Event ID 10 (ProcessAccess)** tagged `technique_id=T1055.001` from the ART test framework's PowerShell orchestration.
- **Event ID 17 (PipeCreate)** — PowerShell named pipe, test framework artifact.

**Security events (4688/4689/4703):** Process create/exit for the PowerShell test framework invocations and a single token right adjustment (4703). No `reg.exe` or `cmd.exe` in the 4688 events — the shortcut was created entirely within PowerShell using COM automation.

The ART test framework boilerplate is visible throughout: repeated `Set-StrictMode -Version 1` fragments across multiple 4104 script block events, `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (4103), and an empty script block loaded from the SYSTEM profile (`C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`).

## What This Dataset Does Not Contain

- **No registry write events.** The Startup folder approach does not touch Run keys; the absence of Sysmon Event ID 13 is expected and meaningful — it differentiates this technique from run-key variants.
- **No `explorer.exe` or logon process activity.** The shortcut was placed but no logon occurred during the collection window, so there is no telemetry of the payload actually executing.
- **No file-system auditing (4663).** Object access auditing is not enabled in this environment, so there is no Security log record of the file write.
- **No DNS or network events.** The target (`calc.exe`) is benign and local; no network activity was generated.
- **No Sysmon Event ID 13 (RegistrySetValue).** As expected — this variant uses the filesystem, not the registry.

## Assessment

The dataset authentically represents a user-space Startup folder persistence attempt on a fully instrumented, Defender-active Windows 11 domain workstation. The technique completed successfully — the .lnk file was created (Sysmon Event 11). Defender did not block this technique, which is consistent with the benign target (`calc.exe`) and the legitimate COM automation path used.

The dataset is dominated by PowerShell test framework overhead: repeated `Set-StrictMode` script blocks (approximately 30 of 38 PowerShell events) are boilerplate from the ART execution framework, not from the test itself. The meaningful signal is concentrated in a small number of events: one FileCreate (Sysmon 11) and the two script block events showing the shortcut-creation code.

## Detection Opportunities Present in This Data

- **Sysmon Event 11:** File creation in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` by a process other than Windows Explorer or legitimate installers is a reliable indicator. The path and `.lnk` extension combination is high-confidence.
- **PowerShell 4104 / 4103:** `New-Object -ComObject WScript.Shell` followed by shortcut creation methods (`CreateShortcut`, `Save`) is a well-known scriptable persistence pattern. The script block content is fully visible in this dataset.
- **PowerShell 4103 module logging:** `CommandInvocation(New-Object)` with `WScript.Shell` parameter is detectable.
- **Process chain:** PowerShell spawned under SYSTEM (`NT AUTHORITY\SYSTEM`) with no interactive parent and command lines consistent with ART test framework invocation provides supporting context.
- **Sysmon Rule annotation:** The sysmon-modular config tagged the FileCreate with `T1187` (Forced Authentication) — a reminder that detection rule annotations can carry false or misleading technique labels depending on the trigger path, not just the action.
