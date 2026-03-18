# T1547.001-20: Registry Run Keys / Startup Folder — Add Persistence via Windows Context Menu

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through registry run keys and startup mechanisms. The Windows Shell context menu can be extended by writing entries under `HKEY_CLASSES_ROOT\Directory\Background\shell\` — these entries define custom items that appear when a user right-clicks on the desktop background. If an adversary adds a `\command` subkey with a malicious executable, that executable will be launched whenever any user right-clicks on the desktop. While this does not fire at every logon automatically like a run key, it provides reliable execution opportunities in interactive user sessions and is a persistence location that many detection tools do not monitor.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that writes a custom context menu command named `Size Modify` under `HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command`, setting the value to `C:\Windows\System32\calc.exe`. The write is performed using `reg add` via `cmd.exe`.

**Sysmon (36 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). `cmd.exe` spawned by PowerShell with command line: `"cmd.exe" /c reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f`. `reg.exe` spawned by `cmd.exe` with the same arguments. Note: The Sysmon EID 1 rule annotation for `reg.exe` and `cmd.exe` shows `technique_id=T1083,technique_name=File and Directory Discovery` — this is a sysmon-modular rule matching on these binaries generally, not a T1547-specific rule.
- EID 7 (Image Load): Multiple DLL loads for three separate PowerShell instances invoked by the test framework during this test window.
- EID 10 (Process Access): PowerShell accessing `whoami.exe` with `0x1FFFFF`.
- EID 11 (File Create): PowerShell startup profile data files for multiple instances.
- EID 17 (Pipe Create): Named pipes from multiple PowerShell instances.

No Sysmon EID 13 (Registry Value Set) event appears for the `HKCR\Directory\Background\shell` path — this path is outside the sysmon-modular monitored registry set.

**Security (12 events):**
- EID 4688/4689: Process creates and exits for `powershell.exe`, `whoami.exe`, `cmd.exe`, `reg.exe`, and `conhost.exe`. The 4688 event for `cmd.exe` records the full `reg add` command line including the `HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command` path and `calc.exe` as the value. The `reg.exe` event similarly records the arguments.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (34 events):**
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- EID 4104: All scriptblock events are PowerShell runtime boilerplate. The test action runs via `cmd.exe /c reg add` and does not appear as a PowerShell scriptblock.

## What This Dataset Does Not Contain

- No Sysmon EID 13 (Registry Value Set) is generated for the `HKCR\Directory\Background\shell` write. The sysmon-modular configuration does not monitor this path, making Sysmon registry monitoring blind to this particular persistence mechanism.
- The context menu entry is created but never triggered — no user right-clicked the desktop during test execution, so there is no execution telemetry for `calc.exe` via this path.
- No PowerShell EID 4104 events capture the test logic — the action runs entirely via `cmd.exe` shell.
- No network connection events appear in this dataset.
- Windows Defender did not block the registry write to `HKCR`.

## Assessment

The test completed successfully. The primary detection surface in this dataset is the Security EID 4688 process creation event for `cmd.exe` and `reg.exe`, which record the full `reg add` command including the `HKEY_CLASSES_ROOT\Directory\Background\shell` path. Sysmon captures the process chain via EID 1 but does not capture the registry write itself.

The absence of a Sysmon EID 13 for the `HKCR\Directory\Background` path is a meaningful coverage gap. Defenders using only Sysmon registry monitoring will not detect this persistence method at the point of write. The process creation telemetry in both Sysmon and the Security log provides the only available detection point from this dataset.

Three separate PowerShell instances are visible in the sysmon data, suggesting the ART test framework spawned multiple invocations during this short window — this is a characteristic of the automated test execution environment and not adversary behavior.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `reg.exe` command line containing `HKEY_CLASSES_ROOT\Directory\Background\shell` and a `\command` subkey path. This is the primary detection surface in this dataset.
- **Sysmon EID 1**: `reg.exe` or `cmd.exe` command line containing `Directory\Background\shell` — Sysmon captures the process creation even without a registry value write event.
- **Pattern**: Any write to `HKCR\Directory\Background\shell\*\command` by a non-system process is a strong persistence indicator. Legitimate shell extension registration is performed by installers, typically with proper code signing, not by `reg.exe` from the command line.
- **Gap to note**: No Sysmon EID 13 is generated for this write. The `HKEY_CLASSES_ROOT\Directory\Background\shell` path should be added to registry monitoring configurations. It is not included in the sysmon-modular default ruleset.
- **Threat hunting**: Enumerating values under `HKCR\Directory\Background\shell\*\command` and `HKCR\Directory\shell\*\command` for unexpected executables across an estate is a productive hunting query.
