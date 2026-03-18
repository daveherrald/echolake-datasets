# T1547.001-2: Registry Run Keys / Startup Folder — Reg Key RunOnce

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folders. This test targets `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`, a lesser-known variant of the `RunOnce` mechanism. `RunOnceEx` entries execute once at the next user logon and are then deleted by the system. Unlike the standard `RunOnce` key, `RunOnceEx` supports a structured subkey hierarchy (`\0001\Depend`, `\0001\Depend\1`) that allows dependency ordering and DLL loading. This enables an adversary to register a DLL for execution at the next logon without using a persistent run key, and without leaving a run key entry that survives beyond the first trigger.

The subkey path used in this test — `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend` — is several levels deeper than the standard `Run` key, which may evade detection rules that only check the top-level run key paths.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-2` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A `cmd.exe` process runs `REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"` to register a DLL reference.

**Sysmon (18 events — EIDs 1, 7, 10, 13, 17):**

EID 1 (ProcessCreate) captures four processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `cmd.exe` (tagged T1059.003, Windows Command Shell) with command line: `"cmd.exe" /c REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"` — the full persistence registration command
- `reg.exe` (tagged T1012, Query Registry — a generic sysmon-modular rule matching `reg.exe`) with the same arguments: `REG  ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"`
- Note: only 4 EID 1 events in the EID breakdown, suggesting no separate cleanup process create is captured in the sample set.

EID 13 (RegistrySetValue) captures the persistence write: `reg.exe` setting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend\1` to `C:\Path\AtomicRedTeam.dll`, annotated `RuleName: technique_id=T1547.001`.

EID 7 (ImageLoad) accounts for 9 events covering PowerShell .NET runtime DLL loads (tagged T1055 and T1574.002 by sysmon-modular — standard PowerShell startup behavior). EID 10 (ProcessAccess) captures PowerShell accessing `whoami.exe` with `GrantedAccess: 0x1FFFFF`. EID 17 (PipeCreate) records the PSHost named pipe.

**Security (4 events — EID 4688):**

Four EID 4688 process creation events:
- `whoami.exe` (identity check)
- `cmd.exe` with full command line: `"cmd.exe" /c REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"`
- `reg.exe` with the same arguments
- A second process (likely the outer `powershell.exe` or cleanup)

All processes ran as `NT AUTHORITY\SYSTEM` (SubjectUserSid `S-1-5-18`, MandatoryLabel `S-1-16-16384`).

**PowerShell (96 events — EIDs 4103, 4104):**

EID 4104 script blocks are PowerShell runtime boilerplate. The test action executes via `cmd.exe /c REG ADD` and does not generate substantive PowerShell script blocks. The cleanup stub is the largest EID 4104 event.

Compared to the defended variant (18 Sysmon, 10 Security, 35 PowerShell), the undefended run produces identical Sysmon event counts (18) and fewer Security events (4 vs. 10). This is the smallest Sysmon dataset in the T1547.001 undefended series — the test involves a single `reg.exe` invocation with no secondary processes, producing a compact and clean event set.

## What This Dataset Does Not Contain

- No execution of `AtomicRedTeam.dll` occurs. The DLL path `C:\Path\AtomicRedTeam.dll` is a placeholder that does not correspond to a real file.
- The `RunOnceEx\0001\Depend` key is deleted at cleanup — both the create and delete operations should be present in the full dataset.
- The `RunOnceEx` mechanism only fires at user logon, so no runtime execution is captured in this dataset.

## Assessment

This is a compact, high-fidelity dataset for a specific `RunOnceEx` persistence registration. The Sysmon EID 13 captures the write with a T1547.001 rule annotation, the Security EID 4688 records the full `reg add` command line, and no background noise obscures the core technique. The identical Sysmon count between the defended and undefended runs (18 events in both) confirms that Defender has no material effect on the telemetry for this specific technique — it is fully visible regardless of endpoint protection state.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 13** with `TargetObject` containing `RunOnceEx` — the `RunOnceEx` path is rarely written to outside of adversarial tooling and some legacy installers. The event carries `RuleName: technique_id=T1547.001` in this dataset.

- **Security EID 4688** recording `cmd.exe` or `reg.exe` with arguments referencing `RunOnceEx` — particularly with a `/d` data value pointing to a `.dll` file rather than an executable. The DLL loading capability of `RunOnceEx` is the distinguishing feature of this variant.

- **Sysmon EID 1** for `cmd.exe` (tagged T1059.003) spawning `reg.exe` with `RunOnceEx` in the arguments, as `NT AUTHORITY\SYSTEM` — an unusual combination outside of software installer behavior.

- **Subkey depth**: `RunOnceEx\0001\Depend\1` is three levels below `RunOnceEx`. Rules that detect only direct `RunOnce` key modifications may miss this pattern. The full `TargetObject` path in the EID 13 event provides the necessary specificity.

- **DLL reference as run key value**: while `Run` and `RunOnce` values typically point to executables, `RunOnceEx\Depend` values are specifically designed for DLLs. A `.dll` path in any `RunOnce*` value is an indicator worth investigating regardless of whether the DLL exists at the specified path.
