# T1547.001-7: Registry Run Keys / Startup Folder — Add Executable Shortcut Link to User Startup Folder

## Technique Context

T1547.001 (Registry Run Keys / Startup Folder) covers persistence mechanisms that cause code to execute automatically at logon. The Startup folder variant places a shortcut (.lnk) file in the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`), causing the linked executable to launch whenever that user logs in. This is one of the most accessible persistence methods on Windows: it requires no elevated privileges for the per-user path, no registry modification, and no special tooling — only the ability to write a file and invoke COM automation through `WScript.Shell`.

This dataset captures the **undefended** execution of ART test T1547.001-7, collected from ACME-WS06 (Windows 11 Enterprise, domain-joined, running as SYSTEM) with Microsoft Defender completely disabled. Comparing with the defended variant (collected from ACME-WS02 with Defender active) is instructive: event counts are nearly identical — sysmon: 39 vs. 39, security: 4 vs. 10, powershell: 110 vs. 38 — because Defender does not block this technique at all. Startup folder shortcut creation is a legitimate Windows operation; Defender does not intervene.

## What This Dataset Contains

The dataset spans a 4-second window (2026-03-17 17:12:02Z to 17:12:06Z) on ACME-WS06 and contains 153 events across three log sources.

**PowerShell script block logging (EID 4104)** captures the exact test payload in a child `powershell.exe` process:

```
$Target = "C:\Windows\System32\calc.exe"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
```

The EID 4103 module logging event records `CommandInvocation(New-Object)` with `ComObject=WScript.Shell`. A total of 107 EID 4104 events are present; the majority are boilerplate ART test framework internal scriptblocks (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }`, error formatting lambdas, `Set-ExecutionPolicy -Bypass`). The meaningful payload content is concentrated in two or three events.

**Sysmon (39 events, EIDs 1, 7, 10, 11, 17):**

- **EID 1 (ProcessCreate):** Four process creates are captured. `whoami.exe` (tagged `T1033`) is the ART test framework identity pre-check. Two `powershell.exe` instances appear: the outer test framework process (PID 17932) and the child that executes the test payload (PID 17272, tagged `T1059.001`). The child `powershell.exe` command line contains the full shortcut-creation script block quoted above.

- **EID 11 (FileCreate):** One file create event — the `.lnk` file written to the user Startup folder. The sysmon-modular ruleset tags this with `technique_id=T1187,technique_name=Forced Authentication` rather than T1547.001, because the config associates `.lnk` file writes in user shell directories with potential forced-authentication relay abuse (UNC path shortcuts) in addition to persistence.

- **EID 10 (ProcessAccess):** Four events tagged `T1055.001 Dynamic-link Library Injection` — the ART test framework parent PowerShell process (PID 17932) opening the child `powershell.exe` and `whoami.exe` with `GrantedAccess: 0x1FFFFF`. This is a consistent test framework artifact: `Start-Process` in .NET acquires a full-access handle to the spawned process; sysmon-modular's broad EID 10 include rule fires on this access pattern.

- **EID 17 (PipeCreate):** Three named pipe creation events for PowerShell host pipes (e.g., `\PSHost.134182411216822712.17932.DefaultAppDomain.powershell`) — standard PowerShell runtime infrastructure artifacts.

- **EID 7 (ImageLoad):** 27 DLL load events for the two PowerShell instances initializing. These are tagged with `T1055 Process Injection` (for CLR DLLs: `mscoree.dll`, `clr.dll`, `clrjit.dll`, `mscorlib.ni.dll`), `T1059.001 PowerShell` (for `System.Management.Automation.ni.dll`), and `T1574.002 DLL Side-Loading` (for Windows Defender DLLs: `MpOAV.dll`, `MpClient.dll`). The Defender DLL loads are present even though Defender is disabled — the platform DLLs are loaded by the PowerShell process at startup regardless of Defender's operational state.

**Security (4 events, all EID 4688):** Process creation records for `whoami.exe` (twice) and both PowerShell instances. Command-line logging is enabled; the full shortcut-creation script is visible in the 4688 record for the child `powershell.exe`.

## What This Dataset Does Not Contain

**No Sysmon EID 13 (RegistrySetValue).** The Startup folder approach does not touch Run keys. The absence of registry write events is expected and meaningful — it distinguishes this technique from the registry Run key variants covered by other T1547.001 tests.

**No payload execution.** The shortcut was written but no logon occurred during the test window. There is no process-create event for `calc.exe` launching from the Startup folder. The persistence mechanism was installed, not triggered.

**No Defender telemetry.** The defended variant shows the same event structure because Defender does not block Startup folder shortcut creation. The difference between defended and undefended for this technique is negligible in practice.

**No object access (Security EID 4663) or registry write (EID 4657) events.** File write auditing and registry object access auditing are not enabled in the audit policy.

**No network events.** This technique is entirely local.

## Assessment

This dataset captures the complete installation of a Startup folder persistence mechanism. The critical artifact is the combination of Sysmon EID 11 (FileCreate in the Startup folder path) and the PowerShell EID 4104 script block showing `WScript.Shell.CreateShortcut()` with a `$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` target path. The Security EID 4688 record independently confirms the process command line.

The undefended and defended datasets are structurally equivalent for this technique. Defender's absence does not change the observable telemetry because shortcut file creation is not a behavior Defender blocks. This makes T1547.001 (Startup folder variant) particularly important to detect through behavioral telemetry rather than endpoint protection.

The 27 EID 7 DLL load events and 107 EID 4104 boilerplate scriptblock events are not indicators of this specific persistence technique — they reflect normal PowerShell process initialization and ART test framework overhead. Analysts focused on this technique should anchor on EID 11 (file creation path) and EID 4104 (script block content mentioning `CreateShortcut` and `Startup`).

## Detection Opportunities Present in This Data

- **Sysmon EID 11:** File creation events at `*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk`. The path and extension together are highly specific to this persistence mechanism. Any process writing a `.lnk` file to a Startup folder is worth investigating.

- **PowerShell EID 4104:** Script blocks referencing `WScript.Shell`, `CreateShortcut`, and a `Startup` path. The combination of these three elements in a single script block is a reliable indicator.

- **PowerShell EID 4103:** `CommandInvocation(New-Object)` with `ComObject=WScript.Shell` provides a lower-fidelity but broader signal for shortcut creation via PowerShell COM automation.

- **Security EID 4688:** Process creation for `powershell.exe` with command-line content containing `WScript.Shell` and `Startup`. Requires command-line auditing to be enabled (confirmed present in this dataset).

- **Correlation:** Pairing EID 11 (file write to Startup folder) with EID 4104 (PowerShell script block) via process GUID or timestamp allows attribution of the write to the specific script that performed it.
