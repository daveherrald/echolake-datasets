# T1562.001-16: Disable or Modify Tools — Tamper with Windows Defender ATP PowerShell

## Technique Context

T1562.001 (Disable or Modify Tools) includes using Windows Defender's own management interface to disable its protection capabilities. The `Set-MpPreference` PowerShell cmdlet is the official Windows Defender configuration API, making this a "living off the land" approach to AV tampering: the attacker uses a legitimate, signed Microsoft component to disable the security product. This test disables four Defender capabilities: real-time monitoring, behavior monitoring, script scanning, and block-at-first-seen. Each is a distinct protection layer, and disabling all four maximally reduces Defender's detection surface.

## What This Dataset Contains

The dataset captures 77 events across Sysmon, Security, and PowerShell logs collected during a 5-second window on 2026-03-14 at 14:50 UTC.

The Defender tamper command is visible in the process creation and PowerShell logs:

```
"powershell.exe" & {Set-MpPreference -DisableRealtimeMonitoring 1
Set-MpPreference -DisableBehaviorMonitoring 1
Set-MpPreference -DisableScriptScanning 1
Set-MpPreference -DisableBlockAtFirstSeen 1}
```

Key observations from the data:

- **Sysmon EID 1**: `powershell.exe` (PID 5148) spawned by the ART test framework `powershell.exe` (PID 5216) with the full multi-line `Set-MpPreference` command block in its command line. RuleName: `technique_id=T1059.001,technique_name=PowerShell`.
- **PowerShell EID 4104**: Two scriptblock events capturing the `Set-MpPreference` block — both the outer invocation `& {Set-MpPreference -DisableRealtimeMonitoring 1 ...}` and the inner script body.
- **PowerShell EID 4103**: Four `CommandInvocation(Set-MpPreference)` events, one per parameter binding, each with full parameter names and values:
  - `DisableRealtimeMonitoring: True`
  - `DisableBehaviorMonitoring: True`
  - `DisableScriptScanning: True`
  - `DisableBlockAtFirstSeen: True`

  Each EID 4103 event also includes a large number of additional `ParameterBinding` entries showing all Set-MpPreference parameters at their current values (QuarantinePurgeItemsAfterDelay, RemoteEncryptionProtectionMaxBlockTime, BruteForce settings, etc.) — these are the full current Defender configuration state, logged by PowerShell's module logging as part of the cmdlet invocation.

- Security EID 4688 records the new `powershell.exe` with the Set-MpPreference command line.
- Sysmon EID 7, 10, 11, 17 provide standard PowerShell test framework artifacts.
- PowerShell EID 4104 also contains ART boilerplate error-handling scriptblocks.

The `Set-MpPreference` cmdlet modifies Windows Defender settings via the WMI/WMI-based interface. Each `Set-MpPreference` invocation succeeds or fails silently; no WDATP block is present in this dataset. The large parameter dumps in EID 4103 are a useful side-effect: they expose the full Defender configuration state at the time of tamper.

## What This Dataset Does Not Contain (and Why)

**No Windows Defender event log entries.** The Microsoft-Windows-Windows Defender/Operational event log (which records EID 5001 for real-time protection disabled, etc.) is not included in the collected channels. This is a gap in the dataset's channel scope, not in the telemetry itself.

**No registry changes visible in Sysmon.** `Set-MpPreference` modifies Defender settings via a COM/WMI interface, not direct registry writes detectable by Sysmon's RegistryEvent rules.

**No Sysmon EID 13 for Defender registry keys.** Even though Defender stores its settings in the registry, the WMI/COM pathway used by Set-MpPreference may bypass direct registry write auditing.

**No evidence that Defender blocked execution.** Running as SYSTEM, `Set-MpPreference` calls succeed. Windows Defender ATP's tamper protection feature (if enabled) would block these calls, but it is not in effect in this environment.

## Assessment

This dataset provides rich PowerShell telemetry for a Defender tampering operation. The four `Set-MpPreference` calls are independently logged in Sysmon (process creation), PowerShell scriptblock logging (EID 4104), and PowerShell module logging (EID 4103), creating three independent detection paths. The EID 4103 events are particularly high fidelity because they record each cmdlet invocation as a structured event with named parameters — this is more reliable than string matching on command lines. The full Defender configuration state visible in the EID 4103 parameter dumps is an unexpected bonus that could support forensic reconstruction of the pre-attack security posture.

## Detection Opportunities Present in This Data

- **PowerShell EID 4103**: `CommandInvocation(Set-MpPreference)` with `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableScriptScanning`, or `DisableBlockAtFirstSeen` parameters set to `True`.
- **PowerShell EID 4104**: Scriptblock containing `Set-MpPreference` with any `Disable*` or tampering parameters.
- **Sysmon EID 1**: `powershell.exe` spawned by `powershell.exe` as SYSTEM with `Set-MpPreference -Disable*` in command line.
- **Security EID 4688**: Child `powershell.exe` with Defender-disabling cmdlet in its command line.
- **Behavioral pattern**: Multiple `Set-MpPreference` calls in rapid sequence disabling distinct protection layers indicates systematic rather than incidental configuration change.
- **Tamper protection**: Windows Defender ATP tamper protection (if enabled) would generate a block event for these Set-MpPreference calls — its absence here represents a detection gap where tamper protection is not active.
