# T1562.006-11: Indicator Blocking — Disable .NET ETW via Environment Variable HKCU Registry - PowerShell

## Technique Context

T1562.006 (Indicator Blocking) covers suppression of security telemetry. This test sets
`COMPlus_ETWEnabled=0` in `HKCU\Environment` using PowerShell's `New-ItemProperty` cmdlet
rather than `reg.exe`. The effect is identical to the cmd/reg.exe variant (T1562.006-10): .NET
ETW is disabled for processes running in the affected user context. Using PowerShell directly
(without spawning reg.exe) produces a different process tree and a different detection footprint,
making it useful for understanding how the same evasion is achieved via different execution paths.

## What This Dataset Contains

The test ran:
`New-ItemProperty -Path HKCU:\Environment -Name COMPlus_ETWEnabled -Value 0 -PropertyType "String" -Force`
in a PowerShell subprocess under NT AUTHORITY\SYSTEM.

**Sysmon EID 1 — process creation (27 events, 2 process-create):**
- `powershell.exe & {New-ItemProperty -Path HKCU:\Environment -Name COMPlus_ETWEnabled -Value 0 -PropertyType "String" -Force}` (parent: WmiPrvSE.exe)
- `whoami.exe`

No reg.exe or cmd.exe spawned — the registry write happens entirely within the powershell.exe
process via the PowerShell provider.

**Sysmon EID 13 — registry value set (1 event):**
```
TargetObject: HKU\.DEFAULT\Environment\COMPlus_ETWEnabled
Details: 0
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```
The writing process is `powershell.exe`, not `reg.exe` — distinguishing this execution path from
the cmd-based variant.

**Security EID 4688 (10 events):** whoami.exe, powershell.exe. No reg.exe. Token Elevation Type 1,
SYSTEM context.

**PowerShell EID 4104 (38 events):** Two test-specific script blocks:
```
& {New-ItemProperty -Path HKCU:\Environment -Name COMPlus_ETWEnabled -Value 0 -PropertyType "String" -Force}
```
and an unwrapped version. The remaining 36 blocks are ART test framework boilerplate.

## What This Dataset Does Not Contain (and Why)

**No reg.exe process:** The cmdlet writes directly to the registry through PowerShell's registry
provider. Detection logic that relies solely on monitoring reg.exe command lines will miss this
technique entirely.

**No Security registry audit events:** `object_access: none` in audit policy means no EID 4657.

**No downstream ETW suppression evidence:** The test sets the value but does not subsequently
launch a .NET process to demonstrate the suppression effect. The value being written is itself
the complete artifact.

## Assessment

This dataset provides the PowerShell-native counterpart to T1562.006-10 and illustrates why
reg.exe-only detection is insufficient for this technique class. The key differences from the
cmd/reg.exe variant: no cmd.exe in the process tree, no reg.exe, and the writing process in
Sysmon EID 13 is powershell.exe. The PowerShell EID 4104 script block provides the clearest
human-readable evidence — `New-ItemProperty ... COMPlus_ETWEnabled ... Value 0` is explicit.

The Sysmon EID 13 indicator is path-based (`HKU\.DEFAULT\Environment\COMPlus_ETWEnabled = 0`)
and is process-agnostic, making it the most reliable cross-variant detection regardless of
whether reg.exe or PowerShell performs the write. Test executed successfully.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** `TargetObject` matching `*\Environment\COMPlus_ETWEnabled` with `Details: 0`, regardless of writing process — covers both this variant and the reg.exe variant
- **PowerShell EID 4104:** Script block containing `New-ItemProperty` and `COMPlus_ETWEnabled` — process-specific indicator for the PowerShell variant
- **Sysmon EID 1:** `powershell.exe` with `New-ItemProperty` and `COMPlus_ETWEnabled` in the command line
- **Security EID 4688:** `powershell.exe` creation under SYSTEM from WmiPrvSE.exe — unusual execution context worth correlating with subsequent registry writes
- **Comparison with T1562.006-10:** The same Sysmon EID 13 registry key/value indicator fires for both cmd and PowerShell variants, while the process-level indicators differ — EID 13 is the more durable detection anchor
