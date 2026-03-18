# T1518.001-8: Security Software Discovery — Security Software Discovery - AV Discovery via Get-CimInstance and Get-WmiObject

## Technique Context

T1518.001 (Security Software Discovery) includes using PowerShell's WMI cmdlets to enumerate registered antivirus products from the `root\SecurityCenter2` (or `root\securitycenter2`) namespace. Both `Get-CimInstance` and `Get-WmiObject` are idiomatic PowerShell interfaces to WMI, and querying `AntiVirusProduct` via either cmdlet is a direct, low-noise way for an adversary to identify installed endpoint protection without spawning external processes like `WMIC.exe`. Because these are native PowerShell cmdlets, they produce rich telemetry in the PowerShell Operational channel — which makes this variant of the technique especially well-covered by endpoint logging when script block and module logging are enabled.

## What This Dataset Contains

The PowerShell channel contains the most direct technique evidence. Event ID 4104 (script block logging) captures both discovery commands verbatim:

```
Get-CimInstance -Namespace root/securityCenter2 -classname antivirusproduct
Get-WmiObject -Namespace root\securitycenter2 -Class antivirusproduct
```

Event ID 4103 (module logging) records `CommandInvocation(Get-CimInstance)` with `ParameterBinding` values `Namespace = "root/securityCenter2"` and `ClassName = "antivirusproduct"`, and separately `CommandInvocation(Get-WmiObject)` with `Namespace = "root\securitycenter2"` and `Class = "antivirusproduct"`. The Host Application field in each 4103 event shows the full command line passed to PowerShell (e.g., `powershell Get-CimInstance -Namespace root/securityCenter2 -classname antivirusproduct`), confirming the precise arguments.

The module logging also captures the setup of CIM cmdlet aliases (`gcim`, `ncim`, `scim`, `rcim`, `icim`, `rcms`, `gcms`, `ncso`, `gcai`, `rcie`, `ncms`, `gcls`) which are part of the CIM module's initialization and can serve as supplementary behavioral markers.

Sysmon event ID 1 captures four process creates: `whoami.exe` (T1033), a `cmd.exe` launcher (T1059.003) with the full command `"cmd.exe" /c powershell Get-CimInstance -Namespace root/securityCenter2 -classname antivirusproduct & powershell Get-WmiObject -Namespace root\securitycenter2 -Class antivirusproduct`, and two `powershell.exe` child instances (both tagged T1059.001) with their individual command lines.

Security event ID 4688 records the same four process creates, confirming the complete process chain: `powershell.exe (test framework) → cmd.exe → powershell.exe (Get-CimInstance) + powershell.exe (Get-WmiObject)`.

## What This Dataset Does Not Contain

No WMI Activity Operational events are included in this dataset. The `Microsoft-Windows-WMI-Activity/Operational` channel was not collected, so event IDs 5857 and 5858 (WMI queries and errors) are absent. These would provide a channel-independent detection layer showing the WQL queries reaching the WMI engine.

No output from either cmdlet is captured — the dataset shows the query execution but not the response. If Defender or another product is registered in SecurityCenter2, its `displayName` would have appeared in the PowerShell output but is not surfaced in the event data.

The Sysmon include-mode configuration did not log the test framework `powershell.exe` via event ID 1 — it was already running before the test window.

## Assessment

This is an excellent dataset for PowerShell-based WMI enumeration detection. The 4104 and 4103 events contain the precise namespace string `root/securityCenter2` (or `root\securitycenter2`) and class name `antivirusproduct` — case-insensitive strings that can be matched without risk of false positives from legitimate administrative workflows. The 4103 `ParameterBinding` events are particularly valuable because they expose the parameter values as structured fields rather than requiring substring matching within a script body. The process-create events (Sysmon ID 1, Security 4688) show cmd.exe running both variants in sequence with full command lines, providing a process-layer detection independent of PowerShell logging. This dataset supports multiple independent detection layers and is suitable for testing SIEM rules, EDR queries, and UEBA models.

## Detection Opportunities Present in This Data

1. **PowerShell 4104 script block containing `root/securityCenter2` or `antivirusproduct`** — Both query variants appear as distinct script blocks and are directly matchable without parsing.
2. **PowerShell 4103 CommandInvocation(Get-CimInstance) with Namespace = root/securityCenter2** — Structured parameter binding in module logging exposes the namespace value as a discrete field, enabling low-false-positive alerting.
3. **PowerShell 4103 CommandInvocation(Get-WmiObject) with Namespace = root\securitycenter2** — Same opportunity for the older `Get-WmiObject` cmdlet; both variants are independently detectable.
4. **Sysmon event ID 1 for powershell.exe with antivirusproduct in command line** — The full command line `powershell Get-CimInstance -Namespace root/securityCenter2 -classname antivirusproduct` is captured verbatim in the CommandLine field.
5. **Security 4688 for cmd.exe with compound AV enumeration command** — The cmd.exe 4688 event captures both `Get-CimInstance` and `Get-WmiObject` calls in a single command line with the SecurityCenter2 namespace, making it a high-confidence single-event detection.
6. **CIM alias initialization in PowerShell module logging** — The batch registration of CIM cmdlet aliases (`gcim`, `icim`, etc.) alongside a SecurityCenter2 query is a corroborating behavioral cluster.
