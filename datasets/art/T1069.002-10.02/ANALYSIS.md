# T1069.002-10: Domain Groups — Enumerate Active Directory Groups with ADSISearcher

## Technique Context

T1069.002 (Domain Groups) covers adversary enumeration of Active Directory groups to map privilege structures, identify high-value targets, and plan lateral movement or privilege escalation paths. The ADSISearcher method is one of the cleanest ways to query Active Directory from PowerShell without importing any additional modules — it uses built-in .NET classes that expose LDAP search functionality through the `[adsisearcher]` type accelerator.

An attacker uses `([adsisearcher]"objectcategory=group").FindAll()` to retrieve all AD group objects in the domain, and `.FindOne()` for a single result. This approach is favored in living-off-the-land (LotL) scenarios because it requires no external tools, no PowerShell module imports, and produces no binary artifacts on disk. The only visible indicators are in PowerShell script block logging (EID 4104) and the LDAP traffic itself. Detection engineering focuses on the `[adsisearcher]` type accelerator in script blocks, LDAP filter strings like `objectcategory=group`, DNS queries to domain controllers, and the characteristic schema cache access pattern that AD queries generate on the querying workstation.

## What This Dataset Contains

The core technique execution is captured in Security EID 4688, which records the PowerShell process spawning with the complete command line:

```
"powershell.exe" & {([adsisearcher]"objectcategory=group").FindAll(); ([adsisearcher]"objectcategory=group").FindOne()}
```

This command creates two ADSISearcher instances targeting all domain group objects via LDAP filter `objectcategory=group`, calling `FindAll()` to enumerate every group and `FindOne()` to retrieve a single result. Sysmon EID 1 confirms this process creation with the same command line visible in the sampled events.

The Sysmon channel provides 38 events across six types: 22 EID 7 (image load), 4 EID 1 (process create), 4 EID 10 (process access), 3 EID 11 (file create), 3 EID 17 (pipe create), and 2 EID 22 (DNS query). The EID 7 events document .NET CLR initialization — `mscoree.dll`, `mscoreei.dll`, and `clr.dll` loading into PowerShell — which is expected when ADSI .NET classes are instantiated. The EID 22 DNS query events capture domain controller name resolution (expected to show `ACME-DC01.acme.local` or similar); ADSISearcher contacts the DC to execute LDAP queries. The EID 11 file creation events indicate PowerShell writing schema cache data, likely to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\acme.local.sch`, which is a standard side-effect of AD enumeration via ADSI — the workstation caches the AD schema locally.

The PowerShell channel has 95 EID 4104 events, dominated by ART test framework boilerplate. The cleanup invocation `Invoke-AtomicTest T1069.002 -TestNumbers 10 -Cleanup -Confirm:$false` is captured in the script block log.

Compared to the defended version (48 sysmon, 11 security, 37 PowerShell events), this undefended run shows significantly more PowerShell volume (95 vs 37) and more Sysmon events (38 vs 48 — slightly fewer, possibly due to Defender's monitoring overhead generating additional events in the defended run). The security count is lower undefended (4 vs 11), reflecting the absence of Defender-triggered audit events.

## What This Dataset Does Not Contain

The dataset does not include network connection telemetry (Sysmon EID 3) for the LDAP traffic to the domain controller. ADSISearcher executes LDAP queries over the network, but this traffic either was not captured by Sysmon's network monitoring configuration or occurred below the log threshold. You will not find the actual group names or group attributes returned by the queries — the enumeration output exists only in process memory and console output.

The PowerShell script block logs contain the test framework boilerplate but the actual `[adsisearcher]` execution command may or may not appear in the 20-event sample; it is present in the EID 4688 process command line instead.

## Assessment

This is a clean, successful execution of ADSI-based domain group enumeration. The command line captured in EID 4688 is highly specific and detectable — the `[adsisearcher]` type accelerator with `objectcategory=group` is rarely seen in legitimate administrative scripting. The DNS resolution events and schema cache file creation provide corroborating indicators of actual LDAP communication with the domain controller.

This dataset executes successfully in the undefended environment (no ACCESS_DENIED exit, more events than the defended blocked run), making it representative of what an attacker achieves when enumeration tools run without interference. The increased PowerShell event volume (95 vs 37) confirms that the script block logging captured substantively more execution activity than in the blocked defended scenario.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `[adsisearcher]` in PowerShell command line**: The type accelerator `[adsisearcher]` in a process command line argument is unusual in normal operations and should be flagged. Combined with `objectcategory=group`, `FindAll()`, or `FindOne()`, the specificity increases substantially.

2. **Sysmon EID 4104 — script block containing ADSI group search**: PowerShell script block logging captures the `[adsisearcher]"objectcategory=group"` expression. Searching EID 4104 for `adsisearcher` combined with group-related LDAP filters (`objectcategory=group`, `objectclass=group`) identifies this pattern without requiring process command line monitoring.

3. **Sysmon EID 22 — DNS resolution of domain controller FQDN**: A DNS query for the domain controller FQDN (`ACME-DC01.acme.local`) from a workstation process that is also creating .NET CLR-related DLL loads indicates LDAP-based AD enumeration is in progress.

4. **Sysmon EID 11 — schema cache file creation**: The creation or modification of files in `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\*.sch` by a PowerShell process is a reliable side-effect indicator of ADSI-based AD queries. This path is not commonly written to by legitimate administrative processes.

5. **Correlation of EID 7 .NET CLR loads + EID 22 DC DNS + EID 11 SchCache**: The co-occurrence of .NET framework DLL loading into PowerShell, a DNS query resolving the domain controller, and a schema cache file write within a short time window is a strong composite indicator of ADSI-based domain enumeration.
