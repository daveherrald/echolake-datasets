# T1548.002-1: Bypass User Account Control — Event Viewer (cmd)

## Technique Context

This test implements the classic UAC bypass via Event Viewer (eventvwr.msc). The technique
exploits the fact that `eventvwr.exe` (which runs auto-elevated without a UAC prompt) reads the
`HKCU\Software\Classes\mscfile\shell\open\command` registry key to locate the default handler for
`.msc` files. By writing a custom command to that key before launching Event Viewer, an attacker
can cause `mmc.exe` — running at high integrity — to spawn an arbitrary process without triggering
a UAC prompt. The payload in this test is `cmd.exe`.

## What This Dataset Contains

**Sysmon (51 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess), EID 12 (RegistryDeleteValue), EID 13 (RegistrySetValue),
EID 22 (DnsQuery). The critical attack chain is fully documented:

- `whoami.exe` (pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f & cmd.exe /c eventvwr.msc`
- `reg.exe` writing `C:\Windows\System32\cmd.exe` to `HKU\.DEFAULT\Software\Classes\mscfile\shell\open\command\(Default)` (Sysmon EID 13)
- `cmd.exe /c eventvwr.msc` launching `mmc.exe "C:\Windows\system32\eventvwr.msc"`
- Sysmon EID 12 (DeleteValue): `MsMpEng.exe` deleting the `mscfile\shell\open\command` key —
  Windows Defender detected and remediated the registry hijack

**Security (22 events):** EID 4688 process creation records document the full chain:
`powershell.exe → cmd.exe → reg.exe`, `cmd.exe → eventvwr.msc`, `cmd.exe → mmc.exe`. EID 4624
(successful logon), EID 4627 (group membership), and EID 4672 (special privileges assigned)
reflect Windows Terminal or WMI service activity within the test window. EID 6416 (new external
device recognized) is ambient system noise. EID 4703 (token right adjusted) captures privilege
adjustment.

**PowerShell (30 events):** Entirely boilerplate ART test framework content — repeated internal PS
error-formatting scriptblocks and `Set-ExecutionPolicy -Bypass` invocations. No attack-specific
PowerShell code appears here because the technique itself used `cmd.exe` and `reg.exe` directly.

**Application (4 events):** EID 15 from Windows Security Center — Defender status updates
(`SECURITY_PRODUCT_STATE_ON`), triggered by Defender's detection activity.

## What This Dataset Does Not Contain (and Why)

**No elevated cmd.exe spawned by mmc.exe** — Windows Defender detected the registry hijack
and deleted the `mscfile\shell\open\command` key (Sysmon EID 12 from `MsMpEng.exe`) before or
shortly after `mmc.exe` launched. Because the key was removed, `mmc.exe` opened Event Viewer
normally rather than spawning the injected `cmd.exe`. The UAC bypass **did not succeed** in
producing an elevated shell.

**No high-integrity process tree from mmc.exe** — had the bypass succeeded, a new `cmd.exe`
with `TokenElevationType=2` (elevated) would appear as a child of `mmc.exe`. That event is
absent, confirming Defender's intervention.

**No Sysmon EID 13 for the HKCU key write** — the dataset shows only the EID 12 delete by
Defender. The EID 13 (SetValue) is present for the `HKU\.DEFAULT` path captured from `reg.exe`'s
execution.

## Assessment

This dataset captures an **attempted but blocked UAC bypass**. The complete attack setup is
visible — registry write via `reg.exe`, launch of `eventvwr.msc`, and `mmc.exe` start — but
Defender's behavioral engine cleaned the registry key before the bypass completed. The EID 12
DeleteValue from `MsMpEng.exe` targeting the hijacked key is the explicit block indicator. This
dataset is valuable for training detectors on the attack setup phase, even when the payload never
executes.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 / Security EID 4688:** `reg.exe` writing to
  `HKCU\Software\Classes\mscfile\shell\open\command` — any write to this key outside of normal
  application registration is suspicious
- **Security EID 4688:** The compound command `reg.exe add hkcu\software\classes\mscfile\shell\open\command ... & cmd.exe /c eventvwr.msc` in a single command line is a well-known UAC bypass pattern
- **Sysmon EID 1 / Security EID 4688:** `mmc.exe` launched from `cmd.exe` (rather than Explorer
  or a service) shortly after a registry write to the mscfile handler key
- **Sysmon EID 12:** `MsMpEng.exe` deleting `HKCU\Software\Classes\mscfile\shell\open\command`
  indicates Defender flagged the hijack — correlate with preceding registry write events
- **Process lineage:** `powershell.exe → cmd.exe → reg.exe + eventvwr.msc` in tight temporal
  proximity is anomalous
