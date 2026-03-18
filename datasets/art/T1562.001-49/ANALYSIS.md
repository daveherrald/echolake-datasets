# T1562.001-49: Disable or Modify Tools — Tamper with Windows Defender Registry - PowerShell

## Technique Context

MITRE ATT&CK T1562.001 covers disabling or modifying security tools. This test performs the same bulk Windows Defender disablement as T1562.001-48, but uses PowerShell's `Set-ItemProperty` cmdlet rather than `reg.exe`. The same 14+ Defender policy values are written to `HKLM:\Software\Policies\Microsoft\Windows Defender` and subkeys. Using a native PowerShell cmdlet instead of `reg.exe` avoids spawning a separate process for each registry write, resulting in a lower process creation footprint. This makes the PowerShell approach somewhat stealthier at the process layer — though PowerShell's own script block and module logging expose the technique fully.

## What This Dataset Contains

**PowerShell (4104 / 4103):** This dataset is dominated by PowerShell telemetry. The 4104 script block log captures the full technique payload:
```powershell
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1
...
```
PowerShell Module Logging (4103) records individual `Set-ItemProperty` cmdlet invocations with parameter bindings for each value:
- `DisableAntiSpyware = 1`, `DisableAntiVirus = 1`, `DisableBehaviorMonitoring = 1`, `DisableIntrusionPreventionSystem = 1`, `DisableIOAVProtection = 1`, `DisableOnAccessProtection = 1`, `DisableRealtimeMonitoring = 1`, `DisableRoutinelyTakingAction = 1`, `DisableScanOnRealtimeEnable = 1`, `DisableScriptScanning = 1`, `DisableEnhancedNotifications = 1`, `DisableBlockAtFirstSeen = 1`, `SpynetReporting = 0`, `MpEnablePus = 0`, `DisallowExploitProtectionOverride = 0`, `TamperProtection = 0`, `SubmitSamplesConsent = 0`, `PUAProtection = 0`

**Security:** Only 12 events — process creation/termination for the test framework PowerShell and `whoami.exe`. No `cmd.exe` or `reg.exe` process creations are present, reflecting the single-process nature of the PowerShell approach.

**Sysmon:** Only 1 event — a network connection event (Sysmon 3). No process create events for child processes, no Sysmon 13 registry write events. The Sysmon ProcessCreate include-mode filter did not match the test framework PowerShell for this execution, and registry monitoring for this path is not captured by the Sysmon config.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 registry write events:** The sysmon-modular configuration's registry event rules did not match the `HKLM\Software\Policies\Microsoft\Windows Defender` path for this execution. The absence is a real coverage gap in registry-only detection approaches.

**No Sysmon 1 process creates for the technique:** Because `Set-ItemProperty` runs in-process within PowerShell, there are no child processes to create. This is precisely why the PowerShell approach has a lower Sysmon process-creation footprint than the `reg.exe` approach in T1562.001-48.

**No confirmation of write success for TamperProtection:** As with T1562.001-48, the `TamperProtection` direct key write may have been blocked by Tamper Protection. PowerShell module logging records the `Set-ItemProperty` call was invoked, but no error or success confirmation is captured in the 4103 event.

**Minimal Sysmon telemetry:** The near-absence of Sysmon data in this dataset illustrates that PowerShell-native registry operations are largely invisible to Sysmon when the ProcessCreate filter doesn't match and registry monitoring rules don't cover the path.

## Assessment

The technique executed successfully for the policy-path writes. PowerShell module logging (4103) provides exceptionally detailed per-value telemetry including parameter bindings, making this dataset ideal for demonstrating the value of PowerShell logging as a detection source when process creation and registry event coverage is limited. The contrast with T1562.001-48 is instructive: the same logical technique, different execution method, very different event distribution across log sources.

## Detection Opportunities Present in This Data

- **PowerShell 4104:** Script block text containing `Set-ItemProperty` with `Windows Defender` policy paths and `Disable` values — single event captures the full technique
- **PowerShell 4103:** Module logging captures each individual `Set-ItemProperty` invocation with parameter name and value — `DisableRealtimeMonitoring = 1` etc. are high-fidelity indicators
- **PowerShell 4103 volume:** 14+ `Set-ItemProperty` cmdlet calls in rapid succession targeting `Windows Defender` subkeys — burst pattern detectable in module logging
- **Security 4688:** PowerShell-spawning-PowerShell pattern from the ART test framework, combined with the absence of child `reg.exe` processes, can help distinguish this variant from the reg.exe variant
- **Absence heuristic:** Heavy PowerShell module logging with Defender policy path references and zero `reg.exe` process creations is a pattern worth modeling for this technique class
