# T1069.001-4: Local Groups — SharpHound3 LocalAdmin Collection

## Technique Context

T1069.001 (Local Groups) covers adversary enumeration of local group memberships, with this test specifically targeting the BloodHound/SharpHound toolchain. SharpHound is BloodHound's data collection component, purpose-built for Active Directory attack path analysis. The `--CollectionMethod LocalAdmin` flag instructs SharpHound to identify local administrator group members across domain-joined systems — a targeted reconnaissance mission that tells an attacker exactly which accounts have administrative access on which machines.

This collection method is broadly used in real-world intrusions because local administrator rights are the primary enabler of lateral movement. An attacker who knows that a service account or a particular user's credentials grant local admin on ten workstations has a mapped attack path. SharpHound gathers this information by making network-based SAM Remote Protocol (SAMR) calls to enumerate local groups on remote systems. Detection engineering focuses on identifying the SharpHound binary (by hash or name), its characteristic network enumeration patterns (high-volume SAMR traffic to many hosts), LDAP queries to the domain controller, and the output ZIP file containing the collected BloodHound data.

The ART test stages SharpHound at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.exe` and invokes it from a PowerShell wrapper that first creates an output directory in `%TEMP%\SharpHound\`.

## What This Dataset Contains

The core SharpHound invocation is visible in Security EID 4688, which captures the full PowerShell command line:

```
"powershell.exe" & {New-Item -Path "$env:TEMP\SharpHound\" -ItemType Directory > $null
& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.exe" -d "$env:UserDnsDomain" --CollectionMethod LocalAdmin --NoSaveCache --OutputDirectory "$env:TEMP\SharpHound\"}
```

This reveals the staging path (`ExternalPayloads\SharpHound.exe`), the domain target (`$env:UserDnsDomain`, which resolves to `acme.local`), the collection method (`LocalAdmin`), and the output directory (`%TEMP%\SharpHound\`). The `--NoSaveCache` flag suppresses SharpHound's local cache file, a minor anti-forensics measure.

Sysmon EID 1 confirms the PowerShell process creation with the full command line, parented to the ART test framework PowerShell process. Notably, the sample set shows no Sysmon EID 1 event for `SharpHound.exe` itself — the binary was invoked but its process creation event falls outside the sampled events. Given 35 total sysmon events (22 EID 7 image loads, 4 EID 1, 4 EID 10, 3 EID 17, 2 EID 11), the SharpHound process creation likely exists in the full dataset but was not captured in the 20-event sample.

The 22 Sysmon EID 7 (image load) events reflect the .NET runtime initialization required for SharpHound (which is a .NET assembly) — `mscoree.dll`, `mscoreei.dll`, `clr.dll`, and associated managed code infrastructure loading into the PowerShell host process. Two Sysmon EID 11 (file creation) events capture filesystem activity consistent with SharpHound output file creation in `%TEMP%\SharpHound\`.

The PowerShell channel contributes 103 events, all EID 4104 script block logging, dominated by ART framework boilerplate. The test cleanup action is captured: `Invoke-AtomicTest T1069.001 -TestNumbers 4 -Cleanup -Confirm:$false`.

Compared to the defended version (37 sysmon, 12 security, 46 PowerShell events), this undefended run produces more PowerShell volume (103 vs 46) but fewer security events (4 vs 12). The defended run's higher security count reflects Defender-generated process monitoring events. Without Defender, the security channel is reduced to the essential process creation events.

## What This Dataset Does Not Contain

The dataset does not contain a Sysmon EID 1 process creation event for `SharpHound.exe` in the sample set, though this event should exist in the full dataset given the process execution. Without it, you cannot directly see the SharpHound binary path from Sysmon process telemetry in the samples provided.

Network activity is absent from the samples — there are no Sysmon EID 3 (network connection) events showing the SAMR calls SharpHound makes to enumerate local admin groups on domain hosts, and no EID 22 (DNS query) events for domain controller or host resolution. These events almost certainly exist in the full dataset given the LocalAdmin collection method requires network access, but they were not captured in the sample window.

The BloodHound output ZIP file that SharpHound generates is referenced by path but its contents are not present in the telemetry. No LDAP query events from the domain controller side are captured (that would require DC-side logging). There is no Sysmon EID 15 (file stream creation) or alternate data stream activity to suggest the output was staged for exfiltration.

## Assessment

This dataset provides clear visibility into the SharpHound invocation from the command line and process creation perspective. The full command with collection method, output directory, and domain target is captured in Security EID 4688 — the most actionable single event for detection. The sysmon data establishes the .NET assembly loading context and file creation artifacts. The absence of SharpHound's own process creation event in the sample is a limitation for training on binary-level detection.

This dataset is most valuable for detecting SharpHound via its command line arguments (particularly `--CollectionMethod LocalAdmin`) and the parent-child process relationship of PowerShell spawning a .NET executable with BloodHound-specific flags. The file creation events pointing to `%TEMP%\SharpHound\` provide an additional indicator for filesystem-based detection.

## Detection Opportunities Present in This Data

1. **Security EID 4688 / Sysmon EID 1 — SharpHound.exe invocation**: The command line contains `SharpHound.exe`, `--CollectionMethod LocalAdmin`, and `--OutputDirectory` pointing to `%TEMP%\SharpHound\`. The combination of the binary name and collection method argument is highly distinctive.

2. **ExternalPayloads staging path**: The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.exe` reveals the ART staging convention, but in real environments, the path would differ. The executable name `SharpHound.exe` in any non-standard path (outside `Program Files`, `Windows`, etc.) is worth flagging.

3. **Sysmon EID 11 — file creation in %TEMP%\SharpHound\**: SharpHound creates a ZIP file containing collected BloodHound data. File creation events in a newly-created temp subdirectory named `SharpHound` by a process running with elevated context is a behavioral indicator.

4. **Sysmon EID 7 — .NET CLR loading into PowerShell prior to external executable launch**: The loading of `mscoree.dll`, `mscoreei.dll`, and `clr.dll` into powershell.exe, followed immediately by a child process creation for a .NET executable, establishes a detectable initialization sequence.

5. **New-Item + binary execution pattern in PowerShell command line**: The PowerShell command creates an output directory immediately before launching the tool, a common staging pattern. Detecting `New-Item` with `-ItemType Directory` in the same command block as a binary execution (especially to `%TEMP%\<toolname>\`) is a useful heuristic.
