# T1518.001-7: Security Software Discovery — AV Discovery via WMI (SecurityCenter2)

## Technique Context

T1518.001 (Security Software Discovery) includes querying the Windows Management Instrumentation (WMI) `SecurityCenter2` namespace to enumerate registered antivirus products. The `root\SecurityCenter2` namespace is maintained by the Windows Security Center service and provides a structured inventory of registered endpoint protection software. Importantly, this query requires no elevated privileges — any user can read the `AntiVirusProduct` class — making it viable from low-integrity contexts. The WMIC command-line client provides a scriptable one-liner that appears in numerous real-world post-exploitation frameworks and offensive toolkits.

In the defended variant (35 Sysmon, 14 Security, 34 PowerShell), the test ran with comparable telemetry. AMSI loaded into WMIC and scanned the command, but the query itself did not trigger a block — `wmic.exe` querying WMI namespaces is a standard administrative operation. This undefended dataset is substantively similar to the defended variant, with the primary difference being the absence of Defender DLL loads into the WMIC process.

## What This Dataset Contains

The dataset spans approximately 5 seconds (2026-03-17 17:06:17–17:06:22 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 135 events across three channels: 107 PowerShell, 23 Sysmon, and 5 Security.

**Security (5 events, EID 4688):** Five process creation events document the complete execution chain:

1. `"C:\Windows\system32\whoami.exe"` — test framework pre-flight
2. `"cmd.exe" /c wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List` — the technique, spawned by `powershell.exe`
3. `wmic.exe` itself as a separate 4688 entry with the full namespace argument
4. `"C:\Windows\system32\whoami.exe"` — post-execution test framework check
5. `"cmd.exe" /c` — cleanup phase

The full WMI query is captured in both the `cmd.exe` command line (as the `cmd.exe /c` argument) and as a separate `WMIC.exe` process creation. All processes run as `NT AUTHORITY\SYSTEM` with creator `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` for the cmd.exe, and `cmd.exe` as creator for WMIC.

**Sysmon (23 events, EIDs 1, 7, 10, 11, 17):** Sysmon EID 1 captures the complete process chain. `cmd.exe` is tagged `T1059.003` with the full WMIC command line in `ParentCommandLine`. A separate EID 1 captures `wmic.exe` — in contrast to the defended variant where sysmon-modular's include-mode config was noted as not matching the WMIC command line, the undefended run's Sysmon captures `cmd.exe` tagged `T1059.003,Windows Command Shell` rather than WMIC directly.

Sysmon EID 7 (ImageLoad) records 13 DLL loads. In the defended variant, EID 7 included `amsi.dll` (tagged `T1059.001`) and `MpOAV.dll` (tagged `T1574.002`) loading into WMIC — confirming Defender's AMSI hook. In this undefended dataset, those Defender-sourced DLL loads are absent. The remaining EID 7 entries reflect standard WMIC dependencies (`wmiutils.dll`, `wbemcomn.dll`, etc.). Sysmon EID 10 fires four times (ProcessAccess from the test framework, tagged `T1055.001`).

**PowerShell (107 events, EIDs 4103, 4104):** The PowerShell channel contains only ART test framework boilerplate. The technique was invoked through `cmd.exe` and `wmic.exe`, so no technique-relevant PowerShell script blocks are captured. EID 4103 records 3 module logging events for test framework infrastructure. EID 4104 records 104 internal formatter stubs.

## What This Dataset Does Not Contain

- **No output of the WMI query.** The `displayName` values returned by the `AntiVirusProduct` query — whether Windows Defender, or any third-party AV registered with Security Center — are not captured in event logs.
- **No Defender AMSI DLL loads.** In the defended variant, Sysmon EID 7 showed `amsi.dll` and `MpOAV.dll` loading into `wmic.exe`. Those Defender-sourced DLL loads are absent here, which is a useful negative indicator: the undefended profile lacks the `T1574.002`-tagged `MpOAV.dll` loads visible in the defended run.
- **No EID 4648 or privilege use events.** The query runs under SYSTEM without explicit credential use.
- **No network activity.** WMI queries to `localhost` are local IPC, not network-based.

## Assessment

This dataset and its defended counterpart tell a consistent story: the WMI SecurityCenter2 query runs without interference in both environments. The difference between defended and undefended is subtle — primarily the presence or absence of Defender's DLL loads into `wmic.exe` (visible in Sysmon EID 7). The core technique evidence — Security EID 4688 carrying the full WMIC command line including the namespace and class name, plus the Sysmon EID 1 parent chain — is present and functionally identical in both.

The undefended run produces slightly fewer total events (135 vs. ~83 in the defended variant) primarily because the PowerShell channel is larger in the undefended run (107 vs. 34 events), reflecting the higher baseline of framework-generated script blocks across the undefended ACME-WS06 test session. The Security channel is comparable (5 vs. 14 in the defended run — the difference being additional 4689 process exit and 4703 token adjustment events captured in the defended run's collection window).

The `wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List` command is a well-known TTP. It appears in numerous threat actor toolkits and is consistently captured via Security EID 4688 (which covers all processes regardless of Sysmon include-mode filtering).

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** `wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List` is captured verbatim in both the `cmd.exe` and `wmic.exe` process creation events. The `SecurityCenter2` namespace string and `AntiVirusProduct` class name are high-fidelity indicators.
- **Sysmon EID 1 parent chain:** `powershell.exe → cmd.exe → wmic.exe` is fully documented. The parent `cmd.exe` command line carries the full namespace argument even when WMIC itself is the target process.
- **Absence of Defender DLL loads (Sysmon EID 7):** The undefended profile lacks `amsi.dll` and `MpOAV.dll` in `wmic.exe`. A Sysmon EID 7 showing WMIC loading these Defender DLLs can serve as an implicit "Defender is present" indicator in a defended environment.
- **Process chain velocity:** `powershell.exe → cmd.exe → wmic.exe` completing in under 2 seconds is characteristic of scripted, automated execution rather than interactive administrative use. The three-process chain appearing as a unit in the Security log is a useful correlation target.
