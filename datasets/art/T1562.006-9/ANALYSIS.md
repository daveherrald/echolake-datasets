# T1562.006-9: Indicator Blocking — PowerShell

## Technique Context

MITRE ATT&CK T1562.006 (Indicator Blocking) includes adversary techniques that suppress
security tool telemetry. This test emulates the LockBit Black variant that disables the
Windows Defender ETW event log channel using native PowerShell cmdlets rather than
`cmd.exe`/`reg.exe`. Functionally identical to T1562.006-8 in its effect, this variant
uses `New-ItemProperty` to write the same `Enabled = 0` registry value, reducing the
process creation footprint by eliminating the `cmd.exe` and `reg.exe` child processes.

## What This Dataset Contains

The test executes:

```powershell
New-ItemProperty
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\
   Microsoft-Windows-Windows Defender/Operational"
  -Name Enabled -PropertyType DWord -Value 0 -Force
```

Security EID 4688 records the `powershell.exe` invocation containing the full command string.
Sysmon EID 1 mirrors this. Sysmon EID 13 (RegistryValueSet) records the actual write:

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\
              Microsoft-Windows-Windows Defender/Operational\Enabled
Details: DWORD (0x00000000)
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

PowerShell EID 4104 captures the `New-ItemProperty` scriptblock verbatim, including both the
outer ART wrapper and the inner command body.

## What This Dataset Does Not Contain (and Why)

No `cmd.exe` or `reg.exe` process creation events are present — this is the key behavioral
difference from T1562.006-8. No network events appear. Object Access auditing is not enabled,
so Security EID 4657 is absent. No System channel events reflecting the Defender log channel
state change are present (System channel not collected).

## Assessment

The test completed successfully; Sysmon EID 13 confirms the registry write with the same
target and value as T1562.006-8. The PowerShell-native variant produces a tighter process
tree but is equally detectable through the registry write and script block log. Detectors
keyed on `reg.exe` command lines would miss this variant; registry-level detections
(Sysmon EID 13) catch both. The PowerShell scriptblock (EID 4104) is particularly valuable
here because the full `New-ItemProperty` invocation appears prior to any technique success,
enabling detection even if registry-level monitoring is unavailable.

The boilerplate EID 4104 fragments are standard ART test framework artifacts.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: `TargetObject` containing `WINEVT\Channels\Microsoft-Windows-Windows
  Defender/Operational\Enabled`, `Details: DWORD (0x00000000)`, image `powershell.exe`.
- **PowerShell EID 4104**: Scriptblock text containing `New-ItemProperty` targeting the
  Defender Operational channel path with `-Value 0`.
- **Security EID 4688**: `powershell.exe` command line with the full Defender channel path
  and `New-ItemProperty`.
- **Paired detection**: Combining this rule (PowerShell `New-ItemProperty` variant) with the
  T1562.006-8 rule (`reg.exe` variant) into a single alert covers both LockBit Black
  implementation paths for this technique.
