# T1548.002-8: Bypass User Account Control — Disable UAC using reg.exe

## Technique Context

T1548.002 (Bypass User Account Control) includes techniques that permanently disable
UAC rather than bypass it on a per-execution basis. This test uses `reg.exe` to set
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` to `0`,
which disables User Account Control globally. This approach requires the ability to write
to HKLM (requiring administrative rights) and persists across reboots. Unlike registry-
hijack bypasses, this is a destructive configuration change rather than a transient
exploit. After the change, all processes on the system auto-elevate without prompting.

This test runs under NT AUTHORITY\SYSTEM via the QEMU guest agent, so it has full access
to HKLM. The ART test includes a cleanup step that restores `EnableLUA` to `1`.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:05:20–00:05:25 UTC).

**Security 4688 — full process chain:**
1. `whoami.exe` — ART pre-check, parent `powershell.exe`
2. `cmd.exe`:
   ```
   "cmd.exe" /c reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
             /v EnableLUA /t REG_DWORD /d 0 /f
   ```
3. `reg.exe`:
   ```
   reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
           /v EnableLUA /t REG_DWORD /d 0 /f
   ```
   All three show `TokenElevationTypeDefault (1)` and Mandatory Label `S-1-16-16384`
   (System), as expected when running under SYSTEM.

**Sysmon Event 13 — registry write confirmed:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA = DWORD (0x00000000)
```
RuleName: `technique_id=T1548.002,technique_name=Bypass User Access Control` — the
sysmon-modular configuration explicitly detects this registry key modification.

**Sysmon Event 1 — three process creates:**
- `whoami.exe` (T1033 rule tag)
- `cmd.exe` (T1059.003 Windows Command Shell rule tag)
- `reg.exe` (T1012 Query Registry rule tag — sysmon-modular tags `reg.exe` under
  registry query/modify detection)

**Security 4703 — token rights adjusted on `powershell.exe`:**
Standard high-privilege right enablement under SYSTEM context.

## What This Dataset Does Not Contain (and Why)

- **The cleanup write (restoring EnableLUA to 1).** The ART cleanup step falls outside
  the telemetry window captured in this dataset. Operators should expect a paired write
  restoring `EnableLUA = 1` if they have broader telemetry.
- **Post-UAC-disable process behavior.** The test only sets the registry key; it does
  not demonstrate processes actually auto-elevating as a result of the UAC-disabled
  state.
- **`reg.exe` process create in Sysmon Event 1 via separate match.** The third Sysmon
  Event 1 shows `reg.exe` tagged under T1012 rather than T1548.002, illustrating that
  the sysmon-modular config reaches this via its registry-tool detection rule, with the
  T1548.002 tag appearing only on the registry write (Event 13).
- **Network activity.** This is a local configuration change; no network events are
  present.

## Assessment

This dataset is an example of UAC disablement rather than bypass. The technique is more
severe than the auto-elevating binary exploits in other tests because it persistently
removes UAC protection for all users on the system. The Sysmon Event 13 with an explicit
T1548.002 rule match provides direct, labeled evidence of the action. The complete
process chain from `powershell.exe` through `cmd.exe` to `reg.exe` is fully captured
in both Security 4688 and Sysmon Event 1 logs.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Write to `HKLM\...\Policies\System\EnableLUA` with value `0` —
  directly tagged by sysmon-modular as T1548.002.
- **Security 4688:** `reg.exe` command line setting `EnableLUA` to `0` under
  `HKLM\...\Policies\System`.
- **Sysmon Event 1:** `reg.exe` spawned by `cmd.exe` spawned by `powershell.exe` with
  the `EnableLUA` key as an argument — low-volume, high-fidelity pattern.
- **Process chain:** `powershell.exe` → `cmd.exe /c reg.exe ADD HKLM\...\EnableLUA`
  is anomalous; legitimate administrative tools use their own UI or Group Policy for
  UAC configuration changes.
- **Security 4703:** SYSTEM-level privilege adjustments immediately before a registry
  write to a security policy key can serve as a contextual escalation indicator.
