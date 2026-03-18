# T1518.001-7: Security Software Discovery — Security Software Discovery - AV Discovery via WMI

## Technique Context

T1518.001 (Security Software Discovery) includes querying the Windows Management Instrumentation (WMI) `SecurityCenter2` namespace to enumerate registered antivirus products. The `root\SecurityCenter2` namespace and its `AntiVirusProduct` class are maintained by the Windows Security Center service and provide a structured inventory of registered endpoint protection software — including product name, version, and status. Attackers favor this approach because it requires no elevated privileges, uses a built-in Windows interface, and returns structured data rather than requiring process name heuristics. The traditional WMIC command-line client provides a scriptable one-liner that has appeared in numerous real-world intrusion toolkits and post-exploitation frameworks.

## What This Dataset Contains

The core technique evidence centers on `WMIC.exe` querying the SecurityCenter2 namespace. Sysmon event ID 1 for `cmd.exe` carries the full command line:

```
"cmd.exe" /c wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
```

This is spawned by `powershell.exe` (confirmed via the 4688 creator process field). Security event ID 4688 records this same cmd.exe creation, as well as a subsequent `WMIC.exe` process creation with the full namespace argument. The parent chain is `powershell.exe → cmd.exe → WMIC.exe`, all as `NT AUTHORITY\SYSTEM`.

Sysmon event ID 7 records DLL loads into the `WMIC.exe` process: `urlmon.dll`, `amsi.dll` (tagged `T1059.001`), `wmiutils.dll` (tagged `T1047`), and Defender's `MpOAV.dll` (tagged `T1574.002`). The `amsi.dll` load is notable — WMIC routes through AMSI on Windows 11, giving Defender a scan hook.

The PowerShell channel contains no technique-relevant script blocks. All 34 events are ART test framework boilerplate (`Set-ExecutionPolicy`, `Set-StrictMode` fragments). The test invokes the command through `cmd.exe` rather than a PowerShell cmdlet, so no PowerShell logging captures the WMI query content.

Security event ID 4688 also records `whoami.exe` spawned by `powershell.exe` as the ART test framework pre-check, providing a baseline for the process chain context.

## What This Dataset Does Not Contain

No PowerShell script block event (4104) contains the `SecurityCenter2` namespace string or `AntiVirusProduct` class name. Detection rules targeting PowerShell logs exclusively would miss this variant.

There are no WMI Activity Operational events (Microsoft-Windows-WMI-Activity/Operational) in this dataset — the WMI channel was not collected for this test. WMI query events (event ID 5857, 5858) would have provided a second, independent detection layer.

The output of the WMIC query — the actual `displayName` value returned — is not captured anywhere in the dataset. There is no file write event showing query results stored to disk.

No Defender block or alert event is present. WMIC querying SecurityCenter2 is a benign-looking operation that Defender does not block by default.

## Assessment

This dataset is useful for process-create–based detection of `WMIC.exe` with the SecurityCenter2 namespace in the command line. Both Security 4688 and Sysmon event ID 1 carry the full command line including `\root\SecurityCenter2` and `AntiVirusProduct`, making the detection string precise. The Sysmon DLL load events for `wmiutils.dll` (tagged T1047) and `amsi.dll` on `WMIC.exe` are supplementary behavioral indicators. To strengthen this dataset, enabling WMI Activity Operational channel collection would add event IDs 5857/5858 showing the WQL query executed, providing a channel-independent detection point. Including a capture of the WMIC output (e.g., written to a temp file) would make it possible to test detection of the reconnaissance result rather than only the attempt.

## Detection Opportunities Present in This Data

1. **Security 4688 for WMIC.exe with SecurityCenter2 in command line** — The full command `wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName` is captured verbatim, enabling precise string matching.
2. **Sysmon event ID 1 for cmd.exe with wmic SecurityCenter2 command** — The cmd.exe wrapper is tagged T1059.003 by sysmon-modular and carries the complete command line including the WMI namespace.
3. **Process chain: powershell.exe → cmd.exe → WMIC.exe** — This three-level chain from a scripting host through a shell to WMIC is anomalous on managed workstations.
4. **Sysmon event ID 7: wmiutils.dll loaded into WMIC.exe, tagged T1047** — Provides a DLL-load–based corroboration of WMI activity, useful as a supplementary indicator.
5. **WMIC.exe execution from a non-interactive SYSTEM context** — `NT AUTHORITY\SYSTEM` spawning WMIC with a SecurityCenter2 namespace query from `C:\Windows\TEMP\` is a high-fidelity behavioral pattern.
