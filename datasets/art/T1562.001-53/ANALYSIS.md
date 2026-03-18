# T1562.001-53: Disable or Modify Tools — AMSI Bypass - Create AMSIEnable Reg Key

## Technique Context

MITRE ATT&CK T1562.001 includes disabling the Antimalware Scan Interface (AMSI). This test creates a registry value `AmsiEnable = 0` under `HKCU:\Software\Microsoft\Windows Script\Settings` (mapped as `HKU\.DEFAULT\Software\Microsoft\Windows Script\Settings` when running as SYSTEM). The Windows Script Host (WSH) component reads this key to determine whether to invoke AMSI scanning before executing scripts. Setting `AmsiEnable = 0` disables AMSI for the WSH engine, which affects `.vbs`, `.js`, and `.wsf` script execution via `wscript.exe` and `cscript.exe`. This is a targeted, per-user bypass that does not affect PowerShell or other AMSI-integrated hosts — it is specifically relevant to script-based attacks using the legacy WSH interpreter.

## What This Dataset Contains

**PowerShell (4104 / 4103):** The technique payload is captured in script block logging:
```powershell
New-Item -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name "AmsiEnable" -Value 0 -PropertyType DWORD -Force
```
Module logging (4103) records `New-Item` creating the `Settings` registry key and `New-ItemProperty` writing `AmsiEnable = 0`.

**Sysmon Event 13:** The registry write is captured:
```
HKU\.DEFAULT\Software\Microsoft\Windows Script\Settings\AmsiEnable = DWORD (0x00000000)
```
The key appears under `HKU\.DEFAULT` because execution is as `NT AUTHORITY\SYSTEM`.

**Sysmon Event 1:** Process creation for `whoami.exe` (test framework pre-check) and the test framework PowerShell invocation with the technique payload as a script block argument. The Sysmon command line for the test framework PowerShell shows the full `New-Item` / `New-ItemProperty` technique code.

**Security (4688):** Process creation for the test framework PowerShell and `whoami.exe`. No child processes are created by the technique since it uses in-process PowerShell cmdlets.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 12 (key create):** The Sysmon configuration does not appear to capture key creation events for the `HKCU\Software\Microsoft\Windows Script` path; only the value write (Event 13) is present.

**No validation of WSH AMSI bypass:** No `wscript.exe` or `cscript.exe` execution is present to confirm that the bypass is effective. The dataset captures the configuration change only.

**No AMSI-related Defender detection:** Writing `AmsiEnable = 0` to the WSH settings path does not trigger a Defender alert on this configuration. The value is a legitimate WSH configuration option, making it less detectable by signature-based approaches.

**No cleanup event:** The test does not appear to clean up the `AmsiEnable = 0` value (unlike the ASR rule tests which delete what they create). The registry write persists after the test completes. This makes the Sysmon 13 event the primary artifact.

## Assessment

The technique executed successfully. The Sysmon 13 event confirming `AmsiEnable = DWORD (0x00000000)` under the WSH settings path is the clearest indicator. The PowerShell 4103 and 4104 logs provide supporting context. This is a low-noise technique — the registry write itself is the primary artifact, and it is not cleaned up by the test. The WSH-specific scope of this bypass (not affecting PowerShell AMSI) is an important characteristic: it is relevant to detections for legacy script engine abuse rather than general PowerShell-based attacks.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Registry write to `HKCU\Software\Microsoft\Windows Script\Settings\AmsiEnable = 0` — highly specific indicator for this exact AMSI bypass
- **PowerShell 4104:** Script block containing `AmsiEnable` and value `0` in the `Windows Script\Settings` path
- **PowerShell 4103:** `New-ItemProperty` with `Name = "AmsiEnable"` and `Value = "0"` — actionable parameter-level detection
- **Sysmon 1:** PowerShell process creation with `AmsiEnable` visible in the command line (when script block is passed as an argument)
- **Persistence heuristic:** `AmsiEnable = 0` in the WSH settings registry path that persists across logon sessions — suitable for periodic registry audit hunting queries
