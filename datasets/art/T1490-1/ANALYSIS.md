# T1490-1: Windows — Delete Volume Shadow Copies

## Technique Context

T1490 (Inhibit System Recovery) via Volume Shadow Copy deletion is one of the most consistently-executed steps in ransomware playbooks. Volume Shadow Copies (VSS) are Windows's built-in point-in-time snapshots and are the primary native recovery mechanism for encrypted files. Ransomware operators delete them — almost universally before or immediately after encryption — to eliminate the victim's ability to restore files without paying. `vssadmin.exe delete shadows /all /quiet` is the canonical command and appears in Ryuk, Conti, LockBit, BlackCat/ALPHV, and many other ransomware families. Detection of this command is considered a Tier 1 ransomware indicator by most security operations teams. `wmic shadowcopy delete` is an alternative that produces different process telemetry but achieves the same result.

## What This Dataset Contains

The test invokes `vssadmin.exe delete shadows /all /quiet`. Security EID 4688 captures the full process chain:

- `powershell.exe` spawns `cmd.exe /c vssadmin.exe delete shadows /all /quiet`
- `cmd.exe` spawns `vssadmin.exe delete shadows /all /quiet`

Sysmon EID 1 captures both: cmd.exe (tagged `technique_id=T1490,technique_name=Inhibit System Recovery`) and vssadmin.exe (also tagged `technique_id=T1490`). Both cmd.exe and vssadmin.exe exit cleanly (`0x0`), confirming successful execution.

The VSS service infrastructure activation is visible in Security EID 4688:
- `VSSVC.exe` (VSS service) started by `services.exe`
- `dllhost.exe /Processid:{293A8973...}` (VSS COM server) started by `services.exe`
- `svchost.exe -k swprv` (Software Shadow Copy Provider) started by `services.exe`

These three processes represent the VSS infrastructure being invoked by vssadmin, confirming the command triggered actual shadow copy operations (deletion in this case).

Security EID 4624/4627/4672 record SYSTEM logon context and special privilege assignment for the VSS operation. Sysmon EID 3 shows Defender (`MsMpEng.exe`) making an outbound HTTPS connection to `48.211.71.202:443` — a cloud lookup triggered by the suspicious activity. The PowerShell channel contains only boilerplate.

## What This Dataset Does Not Contain

There are no Windows System channel events confirming the shadow copies were deleted (e.g., EID 7036 for VSS service status changes or application log entries from the VSS provider). WMI-based shadow deletion (`wmic shadowcopy delete`) would produce different telemetry and is not represented here. File system access to the shadow copy storage (typically `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*`) is not captured since object access auditing is disabled. The Security channel does not include EID 4673 (privileged service called) which some configurations produce during VSS operations.

## Assessment

This is a high-value dataset for T1490 detection engineering. The vssadmin command line is captured with full fidelity in both the Security (4688) and Sysmon (EID 1) channels. The sysmon-modular ruleset explicitly tags both cmd.exe and vssadmin.exe with `technique_id=T1490`, confirming this is a first-class detection target in the configuration. The bonus telemetry from the VSS service infrastructure (VSSVC.exe, dllhost.exe, swprv svchost) starting in response to the deletion is realistic and useful for building deeper behavioral models. The Defender cloud lookup in Sysmon EID 3 is an interesting secondary indicator that AV telemetry itself can signal shadow copy deletion attempts.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1**: `vssadmin.exe delete shadows /all` — direct detection, explicitly tagged `technique_id=T1490` by sysmon-modular; one of the highest-fidelity ransomware precursor indicators available.
2. **Security EID 4688**: `vssadmin.exe delete shadows /all /quiet` with parent `cmd.exe` from `powershell.exe` — command-line detection for the canonical shadow copy deletion command.
3. **Sysmon EID 1**: `cmd.exe /c vssadmin.exe delete shadows` spawned from `powershell.exe` — the scripted invocation pattern rather than interactive command-line use.
4. **Security EID 4688 (VSSVC + dllhost + swprv)**: VSS service infrastructure processes starting from `services.exe` in close temporal proximity to a vssadmin invocation — confirmation that the deletion was actually processed by the VSS subsystem.
5. **Security EID 4688 + 4689 correlation**: vssadmin.exe process creation (exit 0x0) surrounded by VSS service process starts — full causal chain from command invocation to VSS infrastructure response.
6. **Sysmon EID 3**: `MsMpEng.exe` outbound HTTPS connection coinciding with vssadmin execution — Defender cloud lookup as an indirect corroborating signal.
7. **Security EID 4672**: Special privilege assignment to SYSTEM in temporal proximity to shadow copy deletion — elevated context confirmation for the destructive operation.
