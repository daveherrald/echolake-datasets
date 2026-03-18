# T1546.003-1: Windows Management Instrumentation Event Subscription — Persistence via WMI Event Subscription - CommandLineEventConsumer

## Technique Context

T1546.003 (Windows Management Instrumentation Event Subscription) is one of the most detection-resistant persistence mechanisms available to attackers. A WMI subscription consists of three components: an `__EventFilter` (a WQL query that defines what event triggers execution), an `EventConsumer` (defines what to run), and a `FilterToConsumerBinding` (links the filter to the consumer). The `CommandLineEventConsumer` type executes an arbitrary command line when the filter fires. Because WMI subscriptions are stored in the WMI repository (`C:\Windows\system32\wbem\repository\`) rather than the registry, they survive reboots, persist across user logoffs, and are invisible to simple registry-based persistence scans. Attackers favor system uptime events (`Win32_PerfFormattedData_PerfOS_System`) as triggers because they fire reliably on every boot. Detection teams focus on Sysmon events 19/20/21 and WMI-Activity 5861 as primary indicators.

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-13 23:38:06–23:38:12) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (42 events, IDs: 1, 7, 10, 11, 17, 19, 20, 21):** This dataset includes the critical WMI-specific Sysmon events. Sysmon ID=19 (WmiEventFilter) records the filter creation:

```
Name: "AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example"
Query: "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
EventNamespace: "root\CimV2"
```

Sysmon ID=20 (WmiEventConsumer) records the consumer:

```
Name: "AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example"
Type: Command Line
Destination: "C:\Windows\System32\notepad.exe"
```

Sysmon ID=21 (WmiEventConsumerToFilter) records the binding, linking consumer to filter. A Sysmon ID=1 event captures PowerShell spawning as the WMI subscription is being created (tagged T1059.001), and `whoami.exe` (tagged T1033) precedes it as test framework context verification.

**WMI Activity (1 event, ID: 5861):** The `Microsoft-Windows-WMI-Activity/Operational` channel provides a single 5861 event logging the filter-to-consumer binding with the full WQL query and consumer definition:

```
Namespace = //./root/subscription; Eventfilter = AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example; Consumer = CommandLineEventConsumer="AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example"
```

**Security (13 events, IDs: 4688, 4689, 4703):** Process creation events for the test framework PowerShell and whoami. The WMI subscription setup happens in-process and does not generate separate `wmic.exe` or `mofcomp.exe` process creation events since the ART test uses PowerShell WMI cmdlets directly.

**PowerShell (49 events, IDs: 4103, 4104):** Contains test framework boilerplate only. The PowerShell WMI subscription code runs in-process through .NET WMI bindings and is not captured as a distinct script block in the test window.

## What This Dataset Does Not Contain

- **No consumer trigger execution:** The subscription is set to fire when system uptime reaches 240–325 seconds. The test creates the subscription and moves on; no trigger event is present in this 6-second window.
- **No PowerShell WMI subscription script block:** The `New-CimInstance` or `Set-WmiInstance` calls used to create the subscription are executed in-process and do not appear as distinct 4104 script block entries beyond the test framework boilerplate.
- **No WMI-Activity 5859 (filter activation):** Event 5859 is referenced in the 5861 event's message but is not present in the dataset, indicating the filter was not yet activated in this time window.

## Assessment

This is an excellent dataset for WMI persistence detection engineering. The combination of Sysmon IDs 19, 20, and 21 provides complete, structured coverage of all three subscription components, and the WMI-Activity 5861 event provides an independent corroboration from a different channel. The full WQL query — including the trigger condition — is preserved in both channels. The dataset would be strengthened by including a trigger phase showing the `CommandLineEventConsumer` firing and `notepad.exe` (or a real payload) launching from `wmiprvse.exe`. The absence of a Security ID=4688 for `wmiprvse.exe` spawning a child process at trigger time is a known gap in setups without registry-based auditing of WMI consumer execution.

## Detection Opportunities Present in This Data

1. **Sysmon ID=19:** Any `WmiEventFilter` creation (Operation=Created) targeting `Win32_PerfFormattedData_PerfOS_System` in `root\CimV2` is a well-known attacker pattern — alert on all new subscription filter creations.
2. **Sysmon ID=20:** `CommandLineEventConsumer` creation with a destination pointing to any executable outside expected WMI management tools warrants investigation.
3. **Sysmon ID=21:** A `WmiEventConsumerToFilter` binding event (Operation=Created) correlating with an ID=19 and ID=20 from the same time window confirms a complete subscription was registered.
4. **WMI-Activity ID=5861:** The binding event in the WMI-Activity channel is an independent, non-Sysmon detection path. A 5861 event with an unfamiliar filter name and a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` is a reliable indicator.
5. **Sysmon ID=1:** PowerShell spawning under SYSTEM context with subsequent WMI events (19/20/21) within the same short window is a strong composite indicator of automated WMI subscription registration.
