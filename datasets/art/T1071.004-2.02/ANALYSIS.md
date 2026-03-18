# T1071.004-2: DNS — DNS Regular Beaconing

## Technique Context

T1071.004 (Application Layer Protocol: DNS) covers adversaries who use DNS as a covert channel for command-and-control communication. Rather than connecting directly to a C2 server over TCP, an implant encodes data or commands into DNS queries and responses — a technique that bypasses many network-layer controls because DNS traffic is both ubiquitous and frequently excluded from deep inspection. DNS beaconing, the variant exercised here, involves an implant periodically querying a controlled domain to check in with an operator, receive tasking, or exfiltrate small amounts of data one DNS query at a time.

The technique is attractive to real-world attackers for several reasons: DNS requests are made by virtually every process on a domain-joined endpoint, DNS ports (UDP 53) are rarely blocked internally, and many organizations lack DNS visibility at the individual query level. Defenders typically look for high query rates to unusual domains, encoded or randomized subdomains, TXT record queries (commonly used to carry payloads), NXDomain responses at regular intervals, and domains that were recently registered or belong to wildcard DNS providers.

## What This Dataset Contains

This dataset captures the full execution of an ART PowerShell-based DNS beacon (`T1071-dns-beacon.ps1`) against a Windows 11 Enterprise endpoint with Defender disabled. The environment is a domain-joined workstation (ACME-WS06.acme.local) running in the acme.local lab.

The Security log (EID 4688) and Sysmon (EID 1) both record the beacon process being launched with the complete command line visible:

```
"powershell.exe" & {Set-Location "C:\AtomicRedTeam\atomics\"
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain 127.0.0.1.nip.io -Subdomain atomicredteam -QueryType TXT -C2Interval 30 -C2Jitter 20 -RunTime 30}
```

This executes as `NT AUTHORITY\SYSTEM`, launched by a parent PowerShell process (the ART runner), with the full beacon parameters in the clear: domain `127.0.0.1.nip.io`, subdomain prefix `atomicredteam`, query type `TXT`, 30-second check-in interval with 20% jitter, and a 30-second total runtime.

Sysmon EID 22 (DNS query) records four actual beacon queries during the 30-second run window:
- `atomicredteam.416807.127.0.0.1.nip.io`
- `atomicredteam.26203.127.0.0.1.nip.io`
- `atomicredteam.807107.127.0.0.1.nip.io`
- `atomicredteam.723366.127.0.0.1.nip.io`

Each query embedded a randomly generated 5–6 digit number in the subdomain, spaced approximately 30 seconds apart. All returned QueryStatus 9501 (NXDOMAIN), as expected for test domains. The resolving process is `powershell.exe`.

The PowerShell channel (EID 4104, 108 events; EID 4103, 12 events) captures script block logging across the session, including the ART module import (`Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`) and cleanup invocation. The Security log shows 41 EID 4688 process creation events, 4 EID 4624 logon events, and 4 EID 4672 special privilege logon events, along with 17 EID 5379 (credential read) and task scheduler modification events (4698, 4699, 4701, 4702).

Sysmon captures 141 total events across EID 7 (47 image loads), EID 13 (41 registry modifications), EID 11 (24 file creates), EID 10 (12 process access), EID 1 (10 process creates), EID 22 (4 DNS queries), EID 17 (2 named pipe creates), and EID 12 (1 registry key create). The task scheduler channel (164 events) reflects background scheduled tasks firing during the capture window.

Compared to the defended variant (44 sysmon, 25 security, 62 PowerShell events), this undefended dataset is substantially larger — 141 sysmon and 78 security events — because Defender's real-time scanning, AMSI interventions, and automatic process terminations no longer truncate activity. The beacon runs to completion rather than being halted mid-execution.

## What This Dataset Does Not Contain

The target domain (`127.0.0.1.nip.io`) is a wildcard DNS service that maps all subdomains to localhost; no actual C2 infrastructure exists. The DNS queries all resolve to NXDOMAIN rather than returning TXT records with commands, so you will not find events showing command receipt or payload execution after a DNS response.

There are no Sysmon EID 3 (network connection) events associated with the beacon itself because the beacon uses `Resolve-DnsName` (a Windows API call routed through the DNS resolver) rather than making direct TCP/UDP connections. The underlying DNS UDP traffic to the configured DNS server is not represented here as network connection telemetry.

The 30-second runtime means you are seeing a very short beaconing session — four queries. A persistent implant operating over hours or days would produce a much longer query sequence, making interval analysis and domain frequency analysis more tractable.

## Assessment

This is a complete, execution-verified dataset of a DNS beacon operating without interference. The four EID 22 DNS queries are the core adversary artifact — they show the randomized subdomain structure (`<prefix>.<random>.<c2-domain>`) that is characteristic of DNS beacon implementations. Combined with the EID 1 / EID 4688 process creation events exposing the full command line, you have both the mechanism (the script and its parameters) and the effect (the actual queries) in a single capture window.

The dataset represents what an analyst would encounter when a DNS-based implant runs on an endpoint that lacks EDR behavioral blocking. The full fidelity of the PS script block logging, combined with Sysmon DNS telemetry, provides a high-quality example of this technique's observable signature.

The comparison with the defended variant is instructive: in the defended capture, Defender did not block the beacon itself (DNS beaconing via `Resolve-DnsName` is a legitimate API), but the reduced event volume in the defended dataset reflects truncated activity and some event suppression. This undefended dataset shows the full operational footprint.

## Detection Opportunities Present in This Data

**Sysmon EID 22 — DNS query pattern:** Four queries to subdomains of `127.0.0.1.nip.io` with randomized numeric components, all returning NXDOMAIN, spaced ~30 seconds apart. The consistent subdomain prefix (`atomicredteam`), the 5–6 digit random suffix, and the fixed root domain are all observable. The querying process is `powershell.exe` (PID 6728), which is anomalous — PowerShell routinely makes DNS queries for CDN endpoints and update services, but repeated TXT-type NXDOMAIN queries to a single wildcard domain at regular intervals is not normal PowerShell behavior.

**Sysmon EID 1 / Security EID 4688 — Command line exposure:** The complete beacon invocation including domain, subdomain, query type, interval, jitter, and runtime is recorded in the process command line. Any monitoring of PowerShell process creation with command-line capture will see this.

**PowerShell EID 4104 — Script block logging:** The ART test runner script blocks are visible, including the `Invoke-AtomicTest T1071.004 -TestNumbers 2` call and the `Import-Module` for the ART module, providing execution context.

**Timing analysis across EID 22 events:** The four queries are separated by approximately 30 seconds each (with slight jitter), visible in the `_time` field of the Sysmon events. Consistent inter-query intervals to the same domain are a behavioral beacon signature that does not depend on domain reputation.

**EID 4698 / 4699 / 4701 / 4702 — Task scheduler modifications:** Scheduled task creation, deletion, enable, and disable events appear during this capture window, reflecting the ART test framework managing scheduled tasks. These may accompany real-world implant installation if persistence is established alongside C2.
