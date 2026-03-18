# T1562.006-7: Indicator Blocking — PowerShell

## Technique Context

MITRE ATT&CK T1562.006 (Indicator Blocking) includes suppressing .NET CLR ETW instrumentation
via the `HKLM\Software\Microsoft\.NETFramework\ETWEnabled` registry value. This dataset covers
the PowerShell-native variant of the same action documented in T1562.006-6, using
`New-ItemProperty` rather than `cmd.exe`/`reg.exe`. Adversaries often prefer native PowerShell
cmdlets over spawning external binaries because they reduce the process creation footprint and
avoid command-line argument visibility to tools monitoring child processes of `powershell.exe`.

## What This Dataset Contains

The test writes the registry value directly from PowerShell:

```powershell
New-ItemProperty -Path HKLM:\Software\Microsoft\.NETFramework
  -Name ETWEnabled -Value 0 -PropertyType "DWord" -Force
```

Security EID 4688 captures the outer `powershell.exe` invocation with the full command string
embedded as the process command line. Sysmon EID 1 mirrors this. Sysmon EID 13 (RegistryValueSet)
records the write:

```
TargetObject: HKLM\SOFTWARE\Microsoft\.NETFramework\ETWEnabled
Details: DWORD (0x00000000)
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Note the difference from T1562.006-6: here the writing image is `powershell.exe` rather than
`reg.exe`. The PowerShell EID 4104 scriptblocks capture both the outer wrapper and the inner
command body, so the `New-ItemProperty` call is visible in the script block log.

## What This Dataset Does Not Contain (and Why)

No `cmd.exe` or `reg.exe` process creation is present — the registry write is performed
entirely within the PowerShell process. No network events appear. Object Access auditing is
not enabled, so Security EID 4657 is absent. Sysmon EID 12 (key creation) does not fire
because the key already exists.

## Assessment

The test completed successfully. The registry write is confirmed by Sysmon EID 13. Compared
to T1562.006-6, this variant leaves a smaller process tree footprint (no `cmd.exe` or
`reg.exe` child processes) but is equally detectable through the registry modification event
and the PowerShell scriptblock log. The payload appears verbatim in EID 4104, which is
especially valuable because it captures both the dispatched wrapper and the underlying
`New-ItemProperty` invocation.

The boilerplate EID 4104 fragments (`Set-StrictMode`, error handler overhead) are
standard ART test framework artifacts and precede the technique-specific scriptblock.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: `TargetObject` containing `\.NETFramework\ETWEnabled` with `Details:
  DWORD (0x00000000)`, image `powershell.exe` — distinguishes this variant from the `reg.exe`
  variant (T1562.006-6).
- **PowerShell EID 4104**: Scriptblock text containing `New-ItemProperty` with path
  `HKLM:\Software\Microsoft\.NETFramework` and `ETWEnabled` value of `0`.
- **Security EID 4688**: `powershell.exe` process create with command line containing
  `New-ItemProperty` and `\.NETFramework` and `ETWEnabled`.
- **Behavioral**: `powershell.exe` directly modifying `HKLM\Software\Microsoft\.NETFramework`
  without an intermediate `reg.exe` is uncommon and specific enough to detect reliably.
