# T1547.001-18: Registry Run Keys / Startup Folder — Allowing Custom Application to Execute During New RDP Logon Session

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through registry run keys and startup mechanisms. The `StartupPrograms` value under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd` specifies programs that are launched automatically when a new Remote Desktop Protocol (RDP) session is established. By modifying this value, an adversary can cause a program to run every time any user connects via RDP — targeting a specific protocol-level hook that is separate from the standard `Run` or `RunOnce` keys. This is less commonly known than the standard run keys and is unlikely to be covered by detection rules that focus only on `HKCU\...\Run` or `HKLM\...\Run` paths.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that adds `calc` as the `StartupPrograms` value in the RDP stack registry key using `reg add` via `cmd.exe`. This simulates an adversary registering a custom program to launch on each incoming RDP connection.

**Sysmon (27 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). `cmd.exe` spawned by PowerShell with command line: `"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "calc"`. `reg.exe` spawned by `cmd.exe` with the same arguments.
- EID 7 (Image Load): DLL loads for PowerShell — standard .NET runtime behavior.
- EID 10 (Process Access): PowerShell accessing `whoami.exe`.
- EID 11 (File Create): PowerShell startup profile data file.
- EID 17 (Pipe Create): Named pipe from PowerShell.

No Sysmon EID 13 (Registry Value Set) appears in this dataset for the `rdpwd` path. The sysmon-modular include-mode configuration does not include this specific registry path in its monitored targets, so while `reg.exe` successfully wrote the value, Sysmon did not capture the write event.

**Security (12 events):**
- EID 4688/4689: Process creates and exits for both PowerShell instances, `whoami.exe`, `cmd.exe`, `reg.exe`, and `conhost.exe`. The 4688 event for `cmd.exe` records the full `reg add` command including the key path, value name (`StartupPrograms`), and data (`calc`). The `reg.exe` 4688 event similarly records the arguments.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (34 events):**
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- EID 4104: All scriptblock events are PowerShell runtime boilerplate. The actual test command runs via `cmd.exe /c reg add`, not as a PowerShell cmdlet, so no substantive 4104 events are generated for the persistence action itself.

## What This Dataset Does Not Contain

- No Sysmon EID 13 (Registry Value Set) event is present for the `Terminal Server\Wds\rdpwd` path — the sysmon-modular configuration's registry monitoring rules do not include this path, and the write goes uncaptured by Sysmon.
- No actual RDP session is established during the test. The persistence entry is placed, but no RDP logon occurs to trigger execution of the registered program. There is no execution telemetry for the `calc` payload.
- No PowerShell EID 4104 events capture the test logic — the `reg add` is invoked through `cmd.exe`, keeping it outside PowerShell's script block logging.
- No network connection events appear in this dataset.
- Windows Defender did not block the registry write.

## Assessment

The test completed successfully, but Sysmon provides limited visibility here. The key observation is the absence of a Sysmon EID 13 event for this write — the `rdpwd\StartupPrograms` registry path is outside the sysmon-modular monitored set. The primary detection surface is the Security log EID 4688 process creation event for `cmd.exe` and `reg.exe`, which record the full command line including the key path and value.

This test demonstrates a meaningful gap in the sysmon-modular default configuration: registry paths outside the explicitly monitored run key and startup locations are not captured. The Security log's process creation auditing with command-line logging provides complementary coverage and catches what Sysmon misses here.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `reg.exe` process creation with command line containing `Terminal Server\Wds\rdpwd` and `StartupPrograms` in the arguments. This is the primary detection surface in this dataset.
- **Security EID 4688**: `cmd.exe` spawning `reg.exe` with `reg add` and an HKLM system path as a general pattern for registry-based persistence.
- **Sysmon EID 1**: `reg.exe` command line containing `Terminal Server\Wds\rdpwd` — Sysmon captures the process creation even without a registry value write event.
- **Gap to note**: No Sysmon EID 13 is generated for this write. Any detection strategy that relies on Sysmon registry monitoring alone will not alert on this specific persistence path. The `Terminal Server\Wds\rdpwd\StartupPrograms` key path should be added to registry monitoring configurations.
- **Pattern**: Any modification to `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms` is unusual and should be treated as a high-confidence persistence indicator.
