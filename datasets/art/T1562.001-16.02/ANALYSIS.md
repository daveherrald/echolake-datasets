# T1562.001-16: Disable or Modify Tools — Tamper with Windows Defender ATP PowerShell

## Technique Context

T1562.001 (Disable or Modify Tools) includes using Windows Defender's own management interface to disable its protection capabilities. The `Set-MpPreference` PowerShell cmdlet is the official, Microsoft-signed Windows Defender configuration API. Using it to disable Defender is a "living off the land" technique: the attacker leverages a legitimate, trusted tool to undermine the security product, making the action harder to distinguish from legitimate administrator activity.

This test disables four distinct protection layers:
- `-DisableRealtimeMonitoring 1` — disables real-time file and process scanning
- `-DisableBehaviorMonitoring 1` — disables behavior-based detection
- `-DisableScriptScanning 1` — disables PowerShell and script scanning (including AMSI integration)
- `-DisableBlockAtFirstSeen 1` — disables cloud-based first-seen blocking

Disabling all four simultaneously eliminates the most common Defender protection paths for malware execution. Script scanning (`-DisableScriptScanning`) specifically disables Defender's AMSI integration, making it a complement to the AMSI bypass techniques in T1562.001-13 and T1562.001-14 — this approach achieves the same effect via a legitimate API call rather than memory patching or registry deletion.

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-17 17:35:02–17:35:08 UTC) and contains 104 PowerShell events and 3 Security events.

The full attack command is captured in Security EID 4688:
```
"powershell.exe" & {Set-MpPreference -DisableRealtimeMonitoring 1
Set-MpPreference -DisableBehaviorMonitoring 1
Set-MpPreference -DisableScriptScanning 1
Set-MpPreference -DisableBlockAtFirstSeen 1}
```

Security EID 4688 records 3 process creation events: `whoami.exe` (pre-check), the `Set-MpPreference` PowerShell process, and a second `whoami.exe` (post-check). All run as `NT AUTHORITY\SYSTEM`.

The PowerShell events are 99 EID 4104 (script block logging) and 5 EID 4103 (module logging).

The 5 EID 4103 events are the most informative. PowerShell module logging records each `Set-MpPreference` cmdlet invocation with full parameter bindings. Four of the 4103 events correspond to the four `Set-MpPreference` calls, each recording:
- `CommandInvocation(Set-MpPreference): "Set-MpPreference"`
- The specific parameter being set (`DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableScriptScanning`, `DisableBlockAtFirstSeen`) with value `True`
- The complete current Windows Defender configuration state: all additional `ParameterBinding` entries showing the current values of every `Set-MpPreference` parameter (QuarantinePurgeItemsAfterDelay, RemoteEncryptionProtectionMaxBlockTime, brute-force protection settings, submission sample settings, etc.)

This full configuration dump in each EID 4103 event provides a forensic snapshot of the Defender configuration state immediately before each parameter was changed — a valuable artifact for understanding the pre-attack security posture.

The 5th EID 4103 event records `CommandInvocation(Set-ExecutionPolicy)` with `ExecutionPolicy: Bypass` — the standard ART test framework preamble.

The 99 EID 4104 events include the ART boilerplate plus the `Set-MpPreference` script block content. The attack payload IS captured in script block logging here: `Set-MpPreference -DisableRealtimeMonitoring 1` and the other three calls appear as scriptblocks. This is because `Set-MpPreference` is a named cmdlet that PowerShell logs via normal module logging — it does not attempt to bypass AMSI before executing, unlike the InitFailed and registry key approaches.

## What This Dataset Does Not Contain

No Sysmon events. This test falls in the same time window as other T1562.001 tests following the Sysmon driver unload (T1562.001-11). The absence of Sysmon events is consistent with the driver remaining in a degraded or unloaded state throughout this run cluster.

No Windows Defender Application or System log events confirming the preference changes took effect. `Set-MpPreference` modifies Defender's configuration via the WMI-based management interface, but this dataset does not include the Defender-specific event channels (Microsoft-Windows-Windows Defender/Operational) that would record the configuration changes explicitly. The attack's success must be inferred from the command execution rather than from Defender's own logs.

No WMI trace events. The `Set-MpPreference` cmdlet communicates with Defender via WMI internally, but no WMI Operational or Activity events appear for these calls. The WMI channel was either not collected or the specific WMI operations used by Set-MpPreference do not generate the logged event types.

No Security events beyond EID 4688 (no EID 4689 process exits, no EID 4703 token adjustments).

Compared to the defended variant (28 Sysmon, 12 Security, 37 PowerShell), this undefended run has no Sysmon events and slightly more PowerShell events (104 vs 37). The defended variant had Sysmon EID 1 for the attack PowerShell and `whoami.exe` as the primary process creation artifacts, which are absent here due to the Sysmon state.

## Assessment

This technique is particularly notable because it uses Defender's own legitimate management interface. The `Set-MpPreference` cmdlet is documented, signed by Microsoft, and has valid administrative use cases (adjusting scanning exclusions, performance tuning). Detecting its use requires behavioral context — the combination of parameters being disabled, the execution context (SYSTEM, from a test framework PowerShell), and the scope of changes (all four monitoring modes simultaneously).

The EID 4103 module logging provides richer content than most other tests in this dataset. The full Defender configuration dump in each invocation gives analysts a complete picture of the endpoint's Defender state at the time of attack, which is useful for both detection and incident response.

Note that because Defender was disabled in this environment, `Set-MpPreference` in the undefended run modifies settings that were already inactive — the technique's operational impact is redundant in this test context, but the telemetry is identical to what would be generated in a defended environment.

## Detection Opportunities Present in This Data

**Security EID 4688 command line**: `Set-MpPreference -DisableRealtimeMonitoring 1` in a PowerShell process command line spawned from SYSTEM is a high-confidence indicator. The specific combination of all four disabling parameters in a single script block narrows it further. String matching for any of the four `-Disable*` parameters in `Set-MpPreference` calls from non-administrative contexts is a reliable detection approach.

**PowerShell EID 4103 module logging**: `CommandInvocation(Set-MpPreference)` with `ParameterBinding` values of `DisableRealtimeMonitoring: True` is directly logged. This event type is available in any environment with PowerShell module logging enabled, and the parameter name/value pairs are searchable without any parsing beyond standard event log field access.

**Full Defender configuration in EID 4103**: The parameter dump in each EID 4103 event exposes the complete Defender configuration state. An analyst can reconstruct the exact security posture of the endpoint before and after each `Set-MpPreference` call using these events alone.

**Baseline deviation**: In most enterprise environments, `Set-MpPreference` with any `-Disable*` parameter value of `1` (true) represents a deviation from the default configuration. Monitoring for `Set-MpPreference` with disabling parameters as a baseline-deviation event — regardless of execution context — captures both legitimate administrative changes and adversary tampering.

**EID 4103 timing**: Five `Set-MpPreference` invocations within a 6-second window from a SYSTEM context is anomalous. Even legitimate Defender configuration scripts rarely disable four protection layers in rapid succession.
