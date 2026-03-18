# T1572-3: Protocol Tunneling — DNS over HTTPS Long Domain Query

## Technique Context

T1572 (Protocol Tunneling) covers encapsulation of C2 traffic within other protocols.
This test simulates a specific DNS tunneling encoding strategy: encoding data into
unusually long DNS hostnames. Real DNS tunneling tools such as `dnscat2` and `iodine`
encode payload data as base32 or base64 subdomains, producing hostnames that approach
the 253-character DNS name length limit. The test script (`T1572-doh-domain-length.ps1`)
systematically generates DoH TXT queries where the hostname is structured to encode
a three-digit length prefix followed by progressively longer subdomain segments derived
from the string `atomicredteamatomicredteamatomicredteam...`, sweeping the full range
from the minimum useful length up to the 253-character DNS limit.

## What This Dataset Contains

**Sysmon EID 3** — outbound TCP connection from `powershell.exe`:

> `DestinationIp: 8.8.8.8`
> `DestinationPort: 443`
> `SourcePort: 50623`

**PowerShell EID 4104** — the test invocation:

> `{Set-Location "C:\AtomicRedTeam\atomics"`
> `.\T1572\src\T1572-doh-domain-length.ps1 -DohServer https://8.8.8.8/resolve`
> `-Domain 127.0.0.1.xip.io`
> `-Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte`
> `-QueryType TXT}`

And the script body, which reveals the systematic subdomain length enumeration:

> `param([string]$Subdomain = "atomicredteamatomicredteamatomicredteamatomicredteamatomicredte"...)`
> `for($i=$Domain.Length+12; $i -le 253; $i++) {`
> `    $DomainLength = ([string]$i).PadLeft(3, "0")`
> `    $DomainToQuery = $DomainLength + "." + $Subdomain.substring(0, $Subdomain1Length) + "..."`
> `}`

The three-digit zero-padded length prefix (`001.`, `002.`, etc.) as the first label
is a distinctive pattern for domain-length enumeration.

**Security EID 4688** — process creation for `powershell.exe` and `whoami.exe` under
SYSTEM.

**Security EID 4703** — token right adjustment.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 22.** Identical to T1572-1 and T1572-2: DoH bypasses the OS DNS
resolver entirely. The queries go directly to `8.8.8.8:443` as HTTPS POST/GET requests.
No Windows DNS client events are generated.

**No Sysmon EID 1 for PowerShell.** The sysmon-modular include-mode ProcessCreate
filter did not match the `T1572-doh-domain-length.ps1` execution command line. Security
EID 4688 provides command-line coverage.

**No individual query events for the length sweep.** The systematic sweep from minimum
to 253-character DNS names happens entirely within the HTTPS session. Host-level
telemetry captures the script invocation once; the per-query data would require network
inspection.

**No application or WMI side effects.** This test is simpler than T1570-1/2 — it
performs only HTTPS requests, generating no SMB or WMI events.

## Assessment

This is the sparsest of the T1572 datasets: one Sysmon network event, one Security
process create, and the PowerShell script blocks. Its value lies in the detailed script
body captured in EID 4104, which shows the systematic length-based encoding strategy
clearly. In real DNS tunneling, the subdomain content would be encoded payload bytes
rather than the repeated string `atomicredteam...`, but the structure — length-prefixed
labels, maximal-length subdomains, TXT record type queries — would be identical.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104** — `T1572-doh-domain-length.ps1` is directly named; more
  generally, scripts iterating domain lengths from minimum to 253 characters and making
  `Invoke-WebRequest` calls to DoH resolvers indicate systematic DNS tunnel capacity
  testing.
- **Sysmon EID 3** — `powershell.exe` → `8.8.8.8:443`; identical indicator to T1572-1
  and T1572-2. A detector looking for PowerShell HTTPS connections to DNS resolver IPs
  would fire on all three T1572 test variants with a single rule.
- **Network-layer detection** (not in this dataset) — sequential HTTPS requests to
  `8.8.8.8` where the DNS `name` query parameter encodes progressively longer hostnames
  approaching 253 characters would be distinctive in proxy or TLS inspection logs.
- **Correlated EID 4688 + EID 3 timing** — the 18-second window (02:03:57Z to 02:04:15Z)
  for iterating up to ~200 domain length values provides a rate that differs from
  conversational DNS use and should trigger rate-based anomaly detection.
- **TXT record type** — DoH queries requesting TXT records from a PowerShell process
  rather than a mail security service is anomalous; legitimate TXT lookups are infrequent
  and typically domain-specific.
