# T1562.006-13: Indicator Blocking — Disable .NET ETW via Environment Variable HKLM Registry - PowerShell

## Technique Context

T1562.006 (Indicator Blocking) includes disabling ETW for .NET processes. This test combines the
two variants seen separately in tests 11 and 12: system-wide scope (HKLM) via PowerShell's
`New-ItemProperty` cmdlet. Setting `COMPlus_ETWEnabled=0` in
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` using PowerShell:
- Achieves the broadest possible suppression scope (all users, all .NET processes)
- Does so without spawning reg.exe or cmd.exe
- Leaves a strong PowerShell script-block log indicator while avoiding command-line process
  indicators that might trip simpler detections

## What This Dataset Contains

The test ran:
`New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name COMPlus_ETWEnabled -Value 0 -PropertyType "String" -Force`
in a PowerShell subprocess under NT AUTHORITY\SYSTEM.

**Sysmon EID 1 — process creation (37 events, 2 process-create):**
- `powershell.exe & {New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name COMPlus_ETWEnabled -Value 0 -PropertyType "String" -Force}` (parent: WmiPrvSE.exe)
- `whoami.exe`

No cmd.exe or reg.exe spawned.

**Sysmon EID 13 — registry value set (1 event):**
```
TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\Environment\COMPlus_ETWEnabled
Details: 0
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```
The writing process is powershell.exe, distinguishing this from the reg.exe-based HKLM variant
(T1562.006-12).

**Security EID 4688 (10 events):** whoami.exe and powershell.exe only. Token Elevation Type 1,
SYSTEM context. No cmd.exe or reg.exe.

**PowerShell EID 4104 (38 events):** Two test-specific script blocks:
```
& {New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name COMPlus_ETWEnabled -Value 0 -PropertyType "String" -Force}
```
The remaining 36 blocks are ART test framework boilerplate.

## What This Dataset Does Not Contain (and Why)

**No reg.exe or cmd.exe:** The PowerShell registry provider performs the write inline. Detections
based on monitoring reg.exe with specific arguments will not fire for this variant.

**No Security registry audit events (EID 4657):** Object access auditing is disabled in this
environment.

**No observable suppression effect:** No .NET application is launched after the write to
demonstrate that ETW is actually disabled. The dataset ends at the write.

**No rollback events in this window:** The ART cleanup occurs outside the captured timestamp
range.

## Assessment

This dataset completes the 2x2 matrix of ETW suppression via COMPlus_ETWEnabled:

| Hive | Tool | Dataset |
|------|------|---------|
| HKCU | cmd/reg.exe | T1562.006-10 |
| HKCU | PowerShell  | T1562.006-11 |
| HKLM | cmd/reg.exe | T1562.006-12 |
| HKLM | PowerShell  | T1562.006-13 |

Across all four, the Sysmon EID 13 registry write to `*\Environment\COMPlus_ETWEnabled = 0`
is the single consistent indicator. The `Image` field distinguishes reg.exe from powershell.exe
variants. The `TargetObject` path (HKU\* vs. HKLM) distinguishes scope. PowerShell EID 4104 is
the process-specific indicator for the PowerShell variants. Test executed successfully.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 (highest confidence, all variants):** Any write to `*\Environment\COMPlus_ETWEnabled` with value `0` — this single rule covers all four test variants with severity scaled by HKCU (user) vs. HKLM (system-wide)
- **PowerShell EID 4104:** Script block containing `New-ItemProperty` with `COMPlus_ETWEnabled` and `Value 0` — covers tests 11 and 13
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` with `COMPlus_ETWEnabled` in the command line, or `reg.exe` with `COMPlus_ETWEnabled /d 0` — covers tests 10, 12 (reg.exe) and 11, 13 (PS command line)
- **Composite detection:** Absence of reg.exe + presence of Sysmon EID 13 with HKLM path = PowerShell-native registry write targeting system-wide ETW disable (this test specifically)
- **Threat hunting pivot:** Query for `COMPlus_ETWEnabled=0` in `HKLM\...\Session Manager\Environment` across the fleet — persistence check, not just real-time alerting
