# T1087.002-22: Domain Account — Suspicious LAPS Attributes Query with adfind ms-Mcs-AdmPwd

## Technique Context

T1087.002 (Account Discovery: Domain Account) covers adversary attempts to enumerate domain accounts and related attributes from Active Directory. This particular test zeroes in on one of the most high-value discovery sub-techniques available to an attacker who has gained initial access to a domain-joined workstation: querying the Microsoft Local Administrator Password Solution (LAPS) attributes directly from AD.

LAPS stores a unique, randomly-generated local administrator password for each domain-joined machine in two attributes on the computer object: `ms-Mcs-AdmPwd` (the cleartext password) and `ms-Mcs-AdmPwdExpirationTime` (its expiration timestamp). An account with read access to these attributes can trivially recover local admin credentials for every machine in scope — effectively turning a single compromised account into local admin on hundreds of endpoints. Legitimate read access to `ms-Mcs-AdmPwd` is typically restricted to helpdesk groups, privileged admin accounts, and LAPS management software; a domain workstation user or service account performing this query is almost always anomalous.

The test uses AdFind, a widely-abused third-party LDAP query tool, invoked from PowerShell under SYSTEM context to query all computer objects for both LAPS attributes.

## What This Dataset Contains

The dataset spans five seconds of activity (2026-03-14T23:34:48Z–23:34:53Z) on ACME-WS06.acme.local and contains 135 events across four channels.

**The core attack command** appears in both Security EID 4688 and Sysmon EID 1. The Security event shows PowerShell (PID 0xEF4, parent PID 0x3A4) launched with the full command line:

```
"powershell.exe" & {& \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe\"
  -h $env:USERDOMAIN -s subtree -f "objectclass=computer" ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}
```

The `-s subtree` scope and `objectclass=computer` filter target every machine in the domain; `ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime` requests both the password and expiration from each object. All execution occurs under `NT AUTHORITY\SYSTEM` (LogonId 0x3E7, IntegrityLevel System).

**Sysmon EID 1** captures the same PowerShell spawn (PID 3828, parent 932) with full hash context: SHA256 `D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80`. Additionally, `whoami.exe` is captured twice (PIDs 4780 and 2536) as the test framework verifies execution context before and after the main test step — both flagged by Sysmon rule `technique_id=T1033`.

**Sysmon EID 7** (17 events) records the DLL load sequence for the PowerShell process: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, and `System.Management.Automation.ni.dll`, among others. The latter is flagged with rule `technique_id=T1059.001,technique_name=PowerShell`. While these loads are expected for any PowerShell invocation, their presence alongside the suspicious command line provides corroborating timeline context.

**Sysmon EID 10** (3 events) shows PowerShell (PID 932) accessing child processes with full access rights (0x1FFFFF), consistent with the test framework managing child process lifecycle.

**Sysmon EID 17** (2 events) records named pipe creation by PowerShell, consistent with PowerShell remoting pipeline internals.

**PowerShell EID 4104** (103 events) captures script block logging for the execution session. The key block is the AdFind invocation itself. Additional blocks reflect the ART test framework boilerplate: `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'`, `Invoke-AtomicTest T1087.002 -TestNumbers 22 -Cleanup -Confirm:$false`, and standard error-handling closures (`Set-StrictMode -Version 1`). The high block count (103) is a characteristic of how PowerShell's script block logger fragments and re-emits internal runtime closures during module loading.

## What This Dataset Does Not Contain

The AdFind.exe process creation itself is absent. Sysmon's sysmon-modular configuration uses include-mode filtering for ProcessCreate events, and AdFind is not in the rule set — so the tool's own execution (likely spawned by the PowerShell invocation as a child process) generates no EID 1 event. This is a meaningful gap: in a real incident, the absence of an AdFind process creation event would not confirm the tool was blocked; it would merely reflect a coverage gap.

There are no network-layer events showing the LDAP queries to a domain controller. Sysmon EID 3 (network connections) is absent, and there are no DNS resolution events. The AD query traffic itself — the LDAP bind, search request, and response — is not captured in this host-based telemetry set. Netflow or a DC-side LDAP audit would be required to observe the query at the network or directory level.

No Defender detection or blocking events appear anywhere in the dataset. The Application channel's EID 258 and 262 are standard Windows licensing telemetry unrelated to the test.

The dataset does not include the actual LAPS query results. If the querying account had read access to `ms-Mcs-AdmPwd`, AdFind would have returned cleartext passwords; those results are not captured in Windows event telemetry.

## Assessment

This test executed successfully with Defender disabled and produced a complete, high-fidelity record of the LAPS attribute query from the host telemetry perspective. The command line in both Security EID 4688 and Sysmon EID 1 is fully intact and unambiguous, including the specific LAPS attributes targeted. Any detection stack that captures process creation with command-line auditing will see the AdFind invocation with `ms-Mcs-AdmPwd` in the arguments.

Compared to the defended variant — which recorded 32 Sysmon events, 12 Security events, and 45 PowerShell events — the undefended dataset is larger across all channels (26 Sysmon, 3 Security, 103 PowerShell). The higher PowerShell count in the undefended run reflects fuller script block logging fidelity without Defender potentially truncating or suppressing runtime blocks; the lower Security event count (3 vs. 12) in the undefended run suggests the defended environment's additional process creation events came from Defender's own inspection processes spawning in response to the activity.

The critical telemetry — the PowerShell command line containing `AdFind.exe` and `ms-Mcs-AdmPwd` — is present and clean in both variants.

## Detection Opportunities Present in This Data

**Process creation with LAPS attribute names in arguments**: Both Security EID 4688 and Sysmon EID 1 preserve the full command line including the string `ms-Mcs-AdmPwd`. A process creation alert matching `ms-Mcs-AdmPwd` or `ms-Mcs-AdmPwdExpirationTime` in any command-line argument is very high fidelity; there is essentially no legitimate reason for these strings to appear in a process command line on a workstation.

**AdFind.exe execution from non-standard paths**: The binary is invoked from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` — a staging directory, not a normal admin tool location. Any execution of `AdFind.exe` from outside expected IT management paths warrants investigation.

**PowerShell EID 4104 script block content**: The PowerShell logging channel contains the full command including `ms-Mcs-AdmPwd` in the script block text, making script block content a second independent detection surface for this specific query.

**SYSTEM-context PowerShell spawning enumeration tools**: All activity runs under `NT AUTHORITY\SYSTEM` with a parent PowerShell process. A PowerShell process under SYSTEM context spawning further PowerShell children and executing LDAP queries against AD is an unusual pattern on a standard workstation.
