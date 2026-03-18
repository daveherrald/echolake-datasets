# T1546.003-2: Windows Management Instrumentation Event Subscription — Persistence via WMI Event Subscription - ActiveScriptEventConsumer

## Technique Context

T1546.003 (Windows Management Instrumentation Event Subscription) supports multiple consumer types. While the `CommandLineEventConsumer` (covered in T1546.003-1) executes a command, the `ActiveScriptEventConsumer` embeds and executes a VBScript or JScript payload directly within the WMI subscription itself. This is more evasive because the script does not need to be written to disk — it lives entirely within the WMI repository. The script runs inside the `wmiprvse.exe` process, further obscuring attribution. Threat actors including APT33 and BRONZE BUTLER have used `ActiveScriptEventConsumer` for persistent malware loaders. Detection teams monitor the same Sysmon 19/20/21 and WMI-Activity 5861 events as for the CommandLine variant, with particular attention to the consumer `Type: Script` field in Sysmon ID=20.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-13 23:38:23–23:38:28) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (40 events, IDs: 1, 7, 10, 11, 17, 19, 20, 21):** The WMI-specific Sysmon events are the primary technique evidence. Sysmon ID=19 (WmiEventFilter) records the filter:

```
Name: "AtomicRedTeam-WMIPersistence-ActiveScriptEventConsumer-Example"
Query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
EventNamespace: "root\CimV2"
```

Sysmon ID=20 (WmiEventConsumer) captures the critical distinction from the CommandLine variant:

```
Name: "AtomicRedTeam-WMIPersistence-ActiveScriptEventConsumer-Example"
Type: Script
Destination: "\n Set objws = CreateObject(\"Wscript.Shell\")\n objws.Run \"notepad.exe\", 0, True\n "
```

The `Destination` field contains the full embedded VBScript payload, showing `CreateObject("Wscript.Shell")` and `Run "notepad.exe"`. Sysmon ID=21 records the binding. The consumer and filter names differ from the T1546.003-1 dataset, confirming these are distinct test runs with independent subscriptions.

**WMI Activity (1 event, ID: 5861):** Confirms the binding with the full WQL query and `ActiveScriptEventConsumer` name, providing a channel-independent detection path.

**Security (10 events, IDs: 4688, 4689, 4703):** Test framework process creation and termination events only. No distinct process represents the subscription creation since it occurs in-process.

**PowerShell (37 events, IDs: 4103, 4104):** Test framework boilerplate only — `Set-StrictMode` and `Set-ExecutionPolicy Bypass`.

## What This Dataset Does Not Contain

- **No script execution telemetry:** The `ActiveScriptEventConsumer` script runs inside `wmiprvse.exe` when the filter fires. Because the subscription trigger condition (system uptime 240–325 seconds) is not met in this 5-second test window, there is no `wmiprvse.exe` child process or script execution event.
- **No AMSI-related events:** AMSI does not intercept VBScript executed via `ActiveScriptEventConsumer` in `wmiprvse.exe`, so there would be no AMSI telemetry even if the trigger fired.
- **No WMI-Activity 5859:** The filter activation event is not present, consistent with the subscription not yet having fired.
- **No PowerShell script block for the subscription code:** The subscription creation uses in-process WMI .NET bindings and does not generate a meaningful 4104 event.

## Assessment

This is a strong dataset for ActiveScriptEventConsumer-specific detection, particularly because Sysmon ID=20 captures the embedded VBScript payload in the `Destination` field. This is a unique capability — the script content is logged at creation time, not at execution. The Type=Script discriminator in ID=20 distinguishes this from the CommandLine variant and enables consumer-type–specific detections. The dataset is structurally identical to T1546.003-1 in terms of available event types, making the two well-suited for side-by-side use in detection rule development. Adding a triggered execution phase with `wmiprvse.exe` spawning `Wscript.exe` would make this dataset complete for end-to-end detection coverage.

## Detection Opportunities Present in This Data

1. **Sysmon ID=20 (Type=Script):** A `WmiEventConsumer` event with `Type: Script` is a high-fidelity indicator — legitimate WMI administration rarely uses `ActiveScriptEventConsumer`. The embedded VBScript in the `Destination` field can be content-inspected for `CreateObject`, `Shell.Run`, or download cradles.
2. **Sysmon ID=19 + ID=20 correlation:** A filter creation (ID=19) within seconds of a script consumer creation (ID=20) strongly suggests automated subscription setup; this time-based correlation reduces false positives.
3. **WMI-Activity ID=5861:** The independent channel event with `ActiveScriptEventConsumer` in the consumer field enables detection without Sysmon deployed.
4. **Sysmon ID=21:** Binding event confirming filter and consumer are linked — combined with ID=20 `Type=Script`, this triple (19+20+21) is a reliable, low-noise detection cluster.
5. **WMI-Activity 5861 content match:** The full WQL query targeting `Win32_PerfFormattedData_PerfOS_System` with a narrow `SystemUpTime` range is a known persistence trigger pattern; matching this pattern in 5861 events is independently alertable.
