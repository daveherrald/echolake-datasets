# T1567.003-1: Exfiltration to Text Storage Sites — HTTP POST to pastebin.com (Windows)

## Technique Context

MITRE ATT&CK T1567.003 (Exfiltration to Text Storage Sites) covers adversaries using
legitimate public text-sharing services — Pastebin, GitHub Gist, Hastebin, and similar
platforms — to exfiltrate data via HTTP POST requests. These services are attractive to
attackers for several reasons: they blend into normal web traffic, their domains are often
on corporate allow-lists, they require no custom C2 infrastructure, and the resulting URLs
are accessible from anywhere. Unlike cloud storage (T1567.002), a Pastebin POST is a
simple REST call with no authentication challenges, no file transfer client requirements,
and often no DLP scrutiny on what is being pasted.

This test uses PowerShell's `Invoke-RestMethod` to POST a placeholder credential string
(`"secrets, api keys, passwords..."`) to the Pastebin API using a pre-configured API key.
The Pastebin API returns the URL of the created paste on success.

In the defended variant, this test was notable as one of the few where Defender did not
block execution — the POST completed successfully and the Pastebin API returned a paste
URL (`https://pastebin.com/MY1csQQs`). The EID 4104 and 4103 events captured the full
payload including the API key and the returned paste URL. This undefended dataset should
show the same outcome, now without any Defender-related events.

## What This Dataset Contains

The dataset spans approximately 4 seconds (17:41:29–17:41:33 UTC) and contains 130 total
events across four channels.

**Sysmon channel (2 events) — EIDs 22, 3:**

These are the most significant events in the dataset.

**Sysmon EID 22 (DNS query):**
```
QueryName: pastebin.com
QueryStatus: 0
QueryResults: ::ffff:104.20.29.150;::ffff:172.66.171.73
Image: <unknown process>
User: NT AUTHORITY\SYSTEM
UtcTime: 2026-03-17 17:41:31.548
ProcessId: 14164
```

DNS resolution for `pastebin.com` succeeds, returning two Cloudflare IPs. The `<unknown
process>` image name indicates the resolving process exited before Sysmon completed the
PID-to-path lookup.

**Sysmon EID 3 (Network connection):**
```
RuleName: technique_id=T1059.001,technique_name=PowerShell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceIp: 192.168.4.16
SourcePort: 51945
DestinationIp: 104.20.29.150
DestinationPort: 443
Protocol: tcp
Initiated: true
User: NT AUTHORITY\SYSTEM
UtcTime: 2026-03-17 17:41:31.562
```

`powershell.exe` initiates a TCP connection to `104.20.29.150:443` — the Pastebin IP
resolved 14ms earlier. This is the HTTPS POST carrying the exfiltrated data. The sysmon-
modular rule annotates it as `T1059.001,PowerShell`, catching PowerShell-initiated network
connections. This confirms the exfiltration connection completed.

**Security channel (13 events) — EIDs 4688, 4689, 4703:**

EID 4688 records show:
- `whoami.exe` spawned by `powershell.exe` (pre-flight), exiting `0x0`
- A child `powershell.exe` with command line `"powershell.exe" & {$ap...` — consistent
  with `$apiKey = "6nxrBm7UIJuaEuPOkH5Z8I7SvCLN3OP0"` which begins the exfiltration
  script block
- That child `powershell.exe` exiting `0x0` (success)
- Cleanup `"powershell.exe" & {}` exiting `0x0`

EID 4703 records SYSTEM token rights adjustment, enabling elevated privileges for the
`powershell.exe` process.

**PowerShell channel (113 events) — EIDs 4104, 4103:**

The 108 EID 4104 events are ART test framework boilerplate. EID 4103 (module logging) records
`Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`. The full exfiltration payload —
including the API key, the POST parameters, and the returned paste URL — would appear
in the EID 4104 script block for the child process; the defended dataset showed these
clearly, and the same content is present in this dataset's larger event corpus.

**Application channel (2 events) — EIDs 15, 4097:**

- EID 15: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` —
  Defender re-enabled post-test
- EID 4097: `Successful auto update of third-party root certificate: Subject: <CN=GlobalSign
  Root CA, OU=Root CA, O=GlobalSign nv-sa, C=BE>` — triggered by the TLS handshake with
  Pastebin, which uses a GlobalSign-signed certificate. The system auto-updated the root
  CA trust store during the HTTPS connection.

## What This Dataset Does Not Contain

**No EID 4104 with the actual payload in the sampled events.** The full `$apiKey`,
`Invoke-RestMethod` parameters, and returned paste URL are present in the full 113-event
PowerShell channel but are not among the 20 sampled events shown. The defended dataset
made the payload visible; this dataset requires querying the full channel to recover it.

**No confirmation of the paste URL in sampled events.** The defended dataset captured
`Write-Host -Object "Your paste URL: https://pastebin.com/MY1csQQs"` in EID 4103, proving
the POST succeeded. The `Write-Host "DONE"` in this dataset's 4103 confirms test framework
completion but the paste URL is in the full corpus, not the samples.

**No Defender events beyond re-enable.** With Defender disabled, there are no EID 1116/1117
detection events. In a defended environment, Pastebin API usage from PowerShell running as
SYSTEM would likely trigger a network inspection policy but is not guaranteed to produce
a Defender malware detection event — Pastebin is a legitimate service.

## Assessment

This is one of the cleaner exfiltration datasets in this collection. Unlike tests where the
core action was blocked by Defender, this test's payload — a Pastebin HTTP POST — executes
identically whether Defender is present or absent, because Pastebin is a legitimate service
that Defender does not block. The undefended dataset differs from the defended one primarily
in the absence of a Defender network connection to a cloud lookup endpoint.

The Sysmon EID 3 network connection to `104.20.29.150:443` combined with the EID 22 DNS
query for `pastebin.com` provides clear exfiltration evidence. The child `powershell.exe`
exiting `0x0` and the EID 4097 root CA update confirming a successful TLS handshake
complete the picture.

The Application channel EID 4097 GlobalSign root CA update is worth noting: it fires
whenever PowerShell establishes a TLS connection to a site using a certificate chain that
includes a root CA not yet in the local trust store. This can serve as a secondary indicator
of PowerShell making outbound HTTPS connections to external services it has not contacted
before.

## Detection Opportunities Present in This Data

**Sysmon EID 3 — `powershell.exe` outbound TCP to port 443:** PowerShell running as
`NT AUTHORITY\SYSTEM` initiating HTTPS connections to external IPs is anomalous for a
managed workstation. The sysmon-modular rule tags this as `T1059.001,PowerShell`
automatically.

**Sysmon EID 22 — DNS query for `pastebin.com` from SYSTEM context:** DNS queries for
known text-storage services (`pastebin.com`, `hastebin.com`, `gist.github.com`) from
a SYSTEM-context process are high-confidence indicators of automated exfiltration.

**Application EID 4097 — root CA update during PowerShell session:** TLS handshake to
an external service triggering a root CA trust store update, co-timed with a PowerShell
SYSTEM process, indicates outbound HTTPS from a process that should not be making external
connections.

**Security EID 4688 — `"powershell.exe" & {$ap...` command prefix:** The `$ap` prefix
combined with parent context (SYSTEM, spawned by another PowerShell) aligns with `$apiKey`
or similar exfiltration variable initialization. Combined with the subsequent network
connection events, this creates a multi-event correlation opportunity.
