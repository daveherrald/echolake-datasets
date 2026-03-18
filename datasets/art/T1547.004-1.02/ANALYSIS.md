# T1547.004-1: Winlogon Helper DLL — Winlogon Shell Key Persistence (PowerShell, HKCU)

## Technique Context

T1547.004 (Winlogon Helper DLL) covers persistence through modification of Winlogon registry values. The Windows logon process (`winlogon.exe`) reads several registry values during user logon to load shell components. The `Shell` value specifies the interactive shell executable; by appending a comma-separated executable to `explorer.exe`, an attacker causes their payload to launch alongside the desktop every time the user logs on.

This test targets the **HKCU** path (`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`), the per-user variant. Unlike the HKLM version (T1547.004-4), this requires no elevated privileges — any user can modify their own `HKCU` hive. Here the test runs as SYSTEM, but the technique would work for any user. The payload appended is `C:\Windows\System32\cmd.exe`, added after `explorer.exe`.

This dataset captures the **undefended** execution on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02, Defender active) shows identical event structure: 36 sysmon, 10 security, 39 powershell. The absence of Defender interference on this technique is notable — Winlogon shell key modification is not blocked by Defender, making it exclusively a detection challenge.

## What This Dataset Contains

The dataset spans approximately 5 seconds on ACME-WS06 and contains 152 events across three log sources.

**PowerShell EID 4104 and 4103** fully document the test payload:

```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force
```

The EID 4103 module logging event records `CommandInvocation(Set-ItemProperty)` with all parameters: `Path=HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`, `Name=Shell`, `Value=explorer.exe, C:\Windows\System32\cmd.exe`. Both the wrapped (`& {...}`) and unwrapped versions appear in EID 4104 — a consistent ART test framework logging artifact. A cleanup script block (`Remove-ItemProperty`) is also captured in 4104.

**Sysmon (38 events, EIDs 1, 7, 10, 11, 17):**

- **EID 1 (ProcessCreate):** Four process creation events: `whoami.exe` (tagged `T1033`), the attack `powershell.exe` (tagged `T1059.001`) with the `Set-ItemProperty` command visible in the command line, and the cleanup `powershell.exe`.

- **EID 11 (FileCreate):** Two file create events for PowerShell profile data files in `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\` — test framework startup artifacts, not related to the attack.

- **EID 10 (ProcessAccess):** Four events tagged `T1055.001` — test framework parent process acquiring handles to children.

- **EID 17 (PipeCreate):** Three named pipe creation events.

- **EID 7 (ImageLoad):** 25 DLL load events for PowerShell initialization.

- **No EID 13 (RegistrySetValue).** This is the defining feature of this dataset: the HKCU Winlogon Shell modification was performed by PowerShell's `Set-ItemProperty` cmdlet, and it did not generate a Sysmon EID 13 event. The sysmon-modular configuration does not monitor the `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` path. This is a documented detection gap: HKCU-scoped Winlogon monitoring is absent from the ruleset.

**Security (4 events, all EID 4688):** Process creation records for `whoami.exe` and both `powershell.exe` instances, with full command lines. The 4688 for the attack PowerShell instance captures:

```
CommandLine: "powershell.exe" & {Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force}
```

This is the only definitive evidence of the registry modification outside of PowerShell script block logging — Security EID 4688 process command line rather than a dedicated registry event.

## What This Dataset Does Not Contain

**No Sysmon EID 13.** The HKCU Winlogon Shell write is not captured by Sysmon. This is the most significant forensic gap in this dataset. The only log sources documenting the registry modification are PowerShell EID 4104/4103 (script content) and Security EID 4688 (process command line). There is no dedicated registry write event.

**No logon-triggered payload execution.** No logon occurred; `cmd.exe` did not launch from the Winlogon shell mechanism during the test window.

**No `reg.exe` or other registry tooling.** The entire operation was performed through PowerShell's built-in `Set-ItemProperty` cmdlet accessing the PowerShell registry provider (`HKCU:\`). This leaves a lighter tooling footprint than `reg.exe`-based approaches.

## Assessment

This dataset illustrates a critical detection gap: the HKCU Winlogon Shell modification was executed cleanly and completely — the registry was modified, the evidence is in the PowerShell logs, but Sysmon provides no dedicated registry write event for it. The sysmon-modular configuration monitors the HKLM Winlogon path (which generates EID 13, as seen in T1547.004-4) but not the HKCU path.

The consequence is that detection of this technique relies entirely on PowerShell logging being enabled and you examine script block content. This makes HKCU Winlogon Shell persistence less visible than its HKLM counterpart — despite requiring lower privileges, it generates less telemetry.

The defended and undefended datasets are structurally identical for this technique. Defender does not block it.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Script blocks containing `Set-ItemProperty` with a path of `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` and a `Shell` name parameter appending an executable after `explorer.exe`. This is the primary detection source given the Sysmon gap.

- **PowerShell EID 4103:** `CommandInvocation(Set-ItemProperty)` with `Path` containing `Winlogon` and `Name=Shell`. Module logging provides a structured record even when full script block logging captures are overwhelming.

- **Security EID 4688:** `powershell.exe` command lines containing `Winlogon` and `Shell` and `Set-ItemProperty`. Requires command-line logging to be enabled.

- **Sysmon EID 1:** `powershell.exe` process creates with `Winlogon` in the command line, particularly with the `Set-ItemProperty` cmdlet. This is less specific than registry events but provides a process-level anchor.

- **Registry monitoring (not present here):** Direct registry auditing via SACL on `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` would generate Security EID 4657, which is absent from this dataset. Enabling SACL-based registry auditing on the Winlogon key in HKCU would close this gap.
