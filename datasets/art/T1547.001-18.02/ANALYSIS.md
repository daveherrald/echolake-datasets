# T1547.001-18: Registry Run Keys / Startup Folder — Allowing Custom Application to Execute During New RDP Logon Session

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup mechanisms. This test targets the `StartupPrograms` value under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd`, which specifies programs that Windows automatically launches when a new Remote Desktop Protocol (RDP) session is established. By writing to this value, an adversary causes their payload to run each time any user connects via RDP — not at every logon, but specifically at every RDP connection.

This persistence location is less commonly known than the standard `Run` and `RunOnce` keys and is specifically scoped to RDP sessions. Detection tools that monitor only `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` will miss this mechanism entirely. It is particularly relevant in environments where RDP is used for administration, where it becomes a reliable trigger.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-18` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A `cmd.exe` process runs `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "calc"` to register `calc` as the startup program. The cleanup restores the original value (`rdpclip`).

**Sysmon (19 events — EIDs 1, 7, 10, 17):**

EID 1 (ProcessCreate) captures five processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `cmd.exe` (tagged T1083) with command line: `"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "calc"`
- `reg.exe` (tagged T1083) with arguments: `reg  add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "calc"`
- A second `cmd.exe` for cleanup restoring `rdpclip`: `"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "rdpclip"`
- A corresponding second `reg.exe` for the cleanup

The Sysmon EID 1 rule annotations for `cmd.exe` and `reg.exe` show `technique_id=T1083,technique_name=File and Directory Discovery` — sysmon-modular's general rule matching these binaries, not a T1547-specific rule.

**No Sysmon EID 13 (RegistrySetValue) is present in this dataset** for the `Terminal Server\Wds\rdpwd` path. The sysmon-modular include-mode registry monitoring configuration does not include this path in its monitored targets, so `reg.exe` successfully writes the value but Sysmon does not capture the write event. The persistence action is therefore visible only through process creation and Security event auditing.

EID 7 (ImageLoad) produces 9 events for .NET runtime DLL loads during PowerShell initialization. EID 10 (ProcessAccess) captures PowerShell accessing `whoami.exe`. EID 17 (PipeCreate) records the PSHost named pipe.

**Security (5 events — EID 4688):**

Five EID 4688 process creation events provide full command line coverage:
- `whoami.exe` (identity check)
- `cmd.exe` with the full `reg add` command targeting `Terminal Server\Wds\rdpwd` and setting `StartupPrograms` to `calc`
- `reg.exe` with the same arguments
- `cmd.exe` cleanup: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "rdpclip"`
- `reg.exe` for the cleanup

All processes ran as `NT AUTHORITY\SYSTEM`. The `rdpwd` key path, the `StartupPrograms` value name, and the payload `calc` are all captured in plaintext in the EID 4688 command line fields.

**PowerShell (96 events — EIDs 4103, 4104):**

EID 4104 script blocks are entirely PowerShell runtime boilerplate. The test action executes via `cmd.exe /c reg add`, not as a PowerShell cmdlet, so no substantive script blocks are generated for the persistence mechanism itself. The largest EID 4104 block is the ART cleanup stub: `try { Invoke-AtomicTest T1547.001 -TestNumbers 18 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`.

Compared to the defended variant (27 Sysmon, 12 Security, 34 PowerShell), the undefended run produces fewer events across all channels (19 Sysmon, 5 Security, 96 PowerShell). The lower Sysmon and Security counts likely reflect a narrower Cribl Edge collection window, while the higher PowerShell count reflects additional module loading in the undefended execution environment.

## What This Dataset Does Not Contain

- No Sysmon EID 13 for the `StartupPrograms` registry write — the sysmon-modular configuration does not monitor `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd`. Process creation auditing (EID 4688) is the only source showing the write.
- No RDP session is initiated after the modification. No payload execution in an RDP context is captured.
- The `rdpclip` original value (restored during cleanup) confirms the key exists and is functional, but no session-level telemetry is present.

## Assessment

This dataset demonstrates a persistence technique where the process creation logs carry the full forensic story, while Sysmon registry monitoring provides no direct coverage. The `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms` key and value are visible only in the Security EID 4688 `reg.exe` command line argument field. This is an important property for dataset users building detection logic: process command line auditing catches what Sysmon registry monitoring misses for this particular persistence path.

The undefended execution is essentially identical in structure to the defended variant — the `reg.exe` command lines are the same, and neither run produces Sysmon EID 13 for this path.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Security EID 4688** recording `reg.exe` or `cmd.exe` with a command line containing `Terminal Server\Wds\rdpwd` combined with `StartupPrograms` — this specific value name in a `reg add` command has no routine administrative purpose.

- **Security EID 4688** recording any modification to `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd` with a value other than `rdpclip` (the legitimate default) — `rdpclip` is the expected startup program for RDP sessions, and any other value is anomalous.

- **Sysmon EID 1** for `cmd.exe` spawned by `powershell.exe` with a child `reg.exe` targeting Terminal Server configuration paths — the parent-child chain (PowerShell → cmd → reg) touching RDP configuration keys is a meaningful process tree indicator.

- **Absence of Sysmon EID 13**: note that for this specific persistence path, the lack of a registry write event from Sysmon is expected. Detection must rely on EID 4688 command line auditing rather than registry monitoring for this technique variant.
