# T1546-6: Event Triggered Execution — Load Custom DLL on mstsc Execution

## Technique Context

T1546 (Event Triggered Execution) covers persistence mechanisms where an adversary configures the system to execute their payload automatically when a specific event occurs. This test targets a registry-based DLL injection vector for the Remote Desktop client (`mstsc.exe`): writing a value to `HKLM\SOFTWARE\Microsoft\Terminal Server Client\ClxDllPath` causes `mstsc.exe` to load the specified DLL on every launch. Because IT staff and administrators frequently use `mstsc.exe`, this provides a reliable, user-triggered persistence mechanism that fires whenever Remote Desktop connections are made.

The ART test uses `amsi.dll` — a legitimate Windows DLL that already exists at `C:\Windows\System32\amsi.dll` — as the target DLL to register. This avoids the need to drop a malicious DLL and focuses telemetry on the registry modification rather than file creation.

The defended variant of this test produced zero events — the collection window captured nothing. The undefended dataset is the only available telemetry for this persistence technique from this ART test series.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:06:46–17:06:49 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 134 events across three channels: 107 PowerShell, 21 Sysmon, and 6 Security.

**Security (6 events, EID 4688):** Six process creation events document both the setup and the cleanup phases of the test:

Setup phase:
1. `"C:\Windows\system32\whoami.exe"` — test framework pre-flight
2. `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v ClxDllPath /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f` — the persistence registration, spawned by `powershell.exe`
3. `reg  add "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v ClxDllPath /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f` — `reg.exe` process with the full add command

Cleanup phase:
4. `"C:\Windows\system32\whoami.exe"` — post-execution test framework check
5. `"cmd.exe" /c reg delete "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v ClxDllPath /f` — ART cleanup: removing the registry value
6. `reg  delete "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v ClxDllPath /f` — `reg.exe` executing the delete

Both the add and delete operations are fully captured, providing a complete before-and-after record. The target registry key (`HKLM\SOFTWARE\Microsoft\Terminal Server Client`), value name (`ClxDllPath`), and value data (`C:\Windows\System32\amsi.dll`) are present verbatim.

**Sysmon (21 events, EIDs 1, 7, 10, 11, 17):** Sysmon EID 1 captures all six process creations. The setup `cmd.exe` is tagged `RuleName: technique_id=T1059.003,technique_name=Windows Command Shell`. The `reg.exe` add command is tagged `RuleName: technique_id=T1012,technique_name=Query Registry` — the sysmon-modular config uses T1012 as a catch-all for `reg.exe` regardless of whether the operation is a read or write. The cleanup `cmd.exe` (with `reg delete`) is also tagged `T1059.003`, and the cleanup `reg.exe` is tagged `T1012`. Both `whoami.exe` invocations are tagged `T1033`.

Notably, no Sysmon EID 13 (RegistryValueSet) events appear in the 21 surfaced events, and the EID breakdown shows only `7, 10, 1, 11, 17`. The sysmon-modular include-mode configuration for EID 13 did not match the `ClxDllPath` registry path, so the registry write itself is not captured in Sysmon — only in Security EID 4688 via `reg.exe` process creation. EID 7 records 9 DLL load events (`.NET` runtime and PowerShell dependencies). EID 10 fires four times (ProcessAccess from the test framework, GrantedAccess `0x1FFFFF`, tagged `T1055.001`). EID 17 records one named pipe create (`\PSHost.*`). EID 11 records one file creation in the SYSTEM profile path.

**PowerShell (107 events, EIDs 4103, 4104):** All test framework boilerplate. The technique was invoked through `cmd.exe` and `reg.exe`, so no technique-relevant PowerShell script blocks are captured. EID 4103 records 3 module logging events; EID 4104 records 104 formatter stubs.

## What This Dataset Does Not Contain

- **No Sysmon EID 13 (RegistryValueSet).** The registry write to `ClxDllPath` is documented only through `reg.exe` process creation (Security EID 4688, Sysmon EID 1), not through a direct registry event. The sysmon-modular config's EID 13 rules do not appear to target this Terminal Server Client key path.
- **No `mstsc.exe` execution.** The test registers the DLL path but does not launch `mstsc.exe` — the persistence mechanism is configured but not triggered. No EID 7 events show `amsi.dll` loading into `mstsc.exe`, and no `mstsc.exe` process creation events are present.
- **No Defender block events.** The defended dataset had zero events, but this was likely because the test ran too briefly for the Cribl Edge collection pipeline to flush, or because the test completed before any events were generated — not necessarily because Defender blocked the registry write. The undefended dataset confirms the technique does generate telemetry when collected properly.
- **No DLL drop events.** The test uses the pre-existing `amsi.dll` as the payload DLL, so no new file is written to disk.

## Assessment

This dataset provides the only available telemetry for the mstsc DLL hijacking technique from this ART test series. The defended variant was a complete blank — zero events, likely due to the 7-second collection window not capturing any buffered events from the Cribl Edge pipeline. The undefended dataset confirms that when the collection window and pipeline timing align, the technique generates a clean, complete record.

The most important observation is the symmetry between the setup and cleanup phases: you can see the `reg add` establishing the `ClxDllPath` persistence, followed immediately by `reg delete` removing it. In a real intrusion, only the `reg add` would be present (attackers do not clean up their persistence). The ART cleanup operation makes the dataset useful for training detection models to distinguish the setup from the removal pattern.

The absence of Sysmon EID 13 is a coverage gap worth noting for detection engineers: the registry write to `HKLM\SOFTWARE\Microsoft\Terminal Server Client\ClxDllPath` is not captured by sysmon-modular's default EID 13 rules. Process-creation-based detection via `reg.exe` is the primary available indicator in this dataset.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The `reg add` command with the full registry path, value name (`ClxDllPath`), and DLL path (`C:\Windows\System32\amsi.dll`) is captured verbatim. Any write to `HKLM\SOFTWARE\Microsoft\Terminal Server Client\ClxDllPath` via `reg.exe` is a high-fidelity persistence indicator.
- **Sysmon EID 1 for `reg.exe` (tagged T1012):** Both the add and delete operations are captured with full command lines and the `T1012` RuleName. While T1012 is a Query Registry tag, the presence of `reg.exe` with a write operation under this tag is functionally accurate for detection purposes.
- **`reg.exe` spawned by `cmd.exe` spawned by `powershell.exe`:** The three-level chain for a registry persistence operation is anomalous relative to interactive administrative use (where an admin would typically use `regedit.exe` or `Set-ItemProperty`). The scripted `cmd.exe → reg.exe` pattern from a SYSTEM PowerShell host is a behavioral indicator.
- **`ClxDllPath` registry value name:** The value name itself is a high-specificity indicator. In the Security EID 4688 command line, `ClxDllPath` appears in the `reg add` and `reg delete` arguments, providing a reliable string match target.
- **Cleanup signature (reg delete):** The presence of both `reg add ClxDllPath` and `reg delete ClxDllPath` in rapid succession within the same process chain is ART test framework-specific behavior. In a real intrusion, only the add would be present. Detecting the presence of `ClxDllPath` registration without a corresponding prompt deletion is a more realistic hunting target.
