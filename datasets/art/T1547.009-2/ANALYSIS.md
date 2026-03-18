# T1547.009-2: Shortcut Modification — Shortcut Modification - Create Shortcut to cmd in Startup Folders

## Technique Context

T1547.009 (Shortcut Modification) covers adversary abuse of shortcut files for persistence. Test 2 targets the Windows Startup folder specifically — placing a `.lnk` shortcut pointing to `cmd.exe` in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`. Any `.lnk` file in this folder is executed automatically when the user logs on, making it a direct persistence mechanism. This is one of the most commonly observed persistence techniques in the wild, used in commodity malware, RATs, and targeted intrusions alike. Unlike Test 1 which creates a `.url` file in TEMP, this test uses the `WScript.Shell` COM object to programmatically create a properly formatted `.lnk` file in the per-user startup location.

## What This Dataset Contains

The test creates two `.lnk` shortcuts in the Startup folder — one pointing to `cmd.exe` for the per-user startup path and a second using `WScript.Shell` for the all-users startup path. The PowerShell EID 4104 script block is captured in full:

```powershell
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1547.009.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1547.009.";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
[...second shortcut to all-users startup...]
```

Sysmon EID 1 records the PowerShell process (tagged T1083) and `whoami.exe` (T1033). Sysmon EID 11 captures file creation events, including the PowerShell transcript file.

Sysmon event counts: 30 events across EID 1 (2), EID 7 (23), EID 10 (2), EID 11 (3). Security events: 10 events (4688 × 2, 4689 × 7, 4703 × 1).

The PowerShell log (39 events) follows the standard pattern: 37 boilerplate test framework formatter entries plus 2 substantive EID 4104 script block entries.

## What This Dataset Does Not Contain

**Sysmon EID 11 for the .lnk file creation** — surprisingly absent. The sysmon-modular configuration does not have a file creation rule that fires specifically on `.lnk` files in Startup folders, and the EID 11 events captured are PowerShell transcript files. This is a detection coverage gap: the actual shortcut files written to the Startup folders are not recorded in Sysmon.

**The .lnk files are written to the SYSTEM account's APPDATA path** (`C:\Windows\System32\config\systemprofile\...`) because the test runs as SYSTEM, not as an interactive user. In a real-world scenario, the shortcut would be in the logged-on user's Startup folder, but the technique and telemetry pattern are the same.

**No cmd.exe execution at logon** — the shortcut is only triggered at the next interactive user logon, which does not occur during the test window.

**No Security EID 4688 for the .lnk creation** — `.lnk` files are not processes, so their creation does not generate process creation events.

**Object access auditing is disabled**, so no EID 4663 file write events are present.

## Assessment

The test ran to completion. The shortcut creation is confirmed exclusively through PowerShell EID 4104 script block logging — the `WScript.Shell` `CreateShortcut` call and `Save()` are fully visible. Sysmon EID 11 does not capture the actual `.lnk` file drops in this configuration, underscoring the importance of PowerShell script block logging as a complementary detection layer for file-based persistence techniques.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: The `WScript.Shell` COM object instantiation followed by `CreateShortcut()` targeting a Startup folder path is a reliable, low-noise indicator. The target path (`Startup\T1547.009.lnk`) and `TargetPath = "cmd.exe"` are fully visible.
- **PowerShell EID 4104**: `New-Object -ComObject "WScript.Shell"` in combination with Startup folder path strings is a high-value alert condition.
- **Security EID 4688**: The PowerShell process command line includes the Startup folder path, providing detection from a second source.
- A Sysmon EID 11 rule targeting `.lnk` file creation in Startup folder paths (`Programs\Startup\`) would close the detection gap visible in this dataset and should be added to the monitoring configuration.
- **Behavioral correlation**: `whoami.exe` → PowerShell → WScript.Shell COM object → Startup folder write is a compact attack chain that is detectable as a sequence.
