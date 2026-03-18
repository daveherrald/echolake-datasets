# T1071.004-1: DNS — DNS Large Query Volume

## Technique Context

DNS-based command and control represents a sophisticated evasion technique where adversaries tunnel communications through the Domain Name System protocol. This approach exploits DNS's ubiquitous nature and typically permissive firewall policies — most networks allow DNS traffic to flow freely to facilitate normal internet operations. T1071.004 specifically covers DNS as a C2 channel, where attackers can embed commands in DNS queries or responses, exfiltrate data through DNS record requests, or simply generate high volumes of DNS traffic to establish covert channels.

The detection community focuses heavily on DNS anomalies because legitimate DNS usage follows predictable patterns: queries to established domains, reasonable request frequencies, and standard record types. Malicious DNS C2 often exhibits characteristics like requests to suspicious domains, unusual query volumes, non-standard record types, or encoding patterns in hostnames. The "DNS Large Query Volume" variant tested here simulates the high-frequency DNS request pattern common in DNS tunneling or beacon scenarios.

## What This Dataset Contains

This dataset captures a PowerShell-based DNS flooding technique that generates over 1000 DNS TXT record queries to randomly-generated subdomains under `127.0.0.1.nip.io`. The core telemetry shows:

**Sysmon Event ID 22 (DNS Query events):** 1,000+ DNS queries from PowerShell process 18324, all following the pattern `atomicredteam-[RANDOM_NUMBER].127.0.0.1.nip.io` with TXT record requests. Most queries return status code 9501 (DNS_ERROR_RCODE_NO_ERROR but no records found), with one timeout (status 1460).

**Security Event ID 4688 (Process Creation):** Shows the parent PowerShell process (PID 17540) launching the attack PowerShell instance with the command line: `"powershell.exe" & {for($i=0; $i -le 1000; $i++) { Resolve-DnsName -type \"TXT\" \"atomicredteam-$(Get-Random -Minimum 1 -Maximum 999999).127.0.0.1.nip.io\" -QuickTimeout}}`

**PowerShell Event ID 4104 (Script Block Logging):** Captures the exact PowerShell script block that performs the DNS flooding: `{for($i=0; $i -le 1000; $i++) { Resolve-DnsName -type "TXT" "atomicredteam-$(Get-Random -Minimum 1 -Maximum 999999).127.0.0.1.nip.io" -QuickTimeout}}`

**System Event ID 1014:** A single DNS timeout event for query `atomicredteam-946488.127.0.0.1.nip.io`, indicating at least one query exceeded the timeout threshold.

**Sysmon Process Creation (EID 1):** Limited process telemetry due to sysmon-modular's include-mode filtering, but captures the PowerShell processes involved and a `whoami.exe` execution.

## What This Dataset Does Not Contain

The dataset primarily focuses on the DNS query generation and lacks deeper network-level artifacts. Missing elements include:

**Network Connection Events:** No Sysmon Event ID 3 (Network Connection) events, likely because DNS queries use connectionless UDP and may not trigger connection logging in the sysmon-modular configuration.

**DNS Server Responses:** While we see query status codes, the actual DNS response content and payload sizes are not captured in the Windows event logs.

**Parent Process Context:** Limited visibility into the full process chain that initiated the attack, as the test framework execution details are minimal.

**Timing Analysis Data:** While timestamps are present, there's no high-resolution timing data to analyze query intervals and patterns that might indicate automation.

## Assessment

This dataset provides excellent coverage for detecting DNS-based command and control through volume-based analytics. The Sysmon DNS query logging (EID 22) delivers comprehensive visibility into the attack pattern, capturing every individual query with process attribution, query names, status codes, and timestamps. The complementary PowerShell script block logging provides the complete attack methodology, making this dataset ideal for developing both behavioral and content-based detections.

The Security audit events add valuable process-level context, while the single System timeout event demonstrates how DNS infrastructure stress manifests in Windows logging. For detection engineering focused on DNS C2, this dataset offers robust signal coverage across multiple log sources. The primary limitation is the lack of network-layer telemetry, but the application-layer visibility is comprehensive.

## Detection Opportunities Present in This Data

1. **DNS Query Volume Threshold Detection** — Monitor for processes generating >100 DNS queries within a 5-minute window, particularly from scripting engines like PowerShell

2. **Suspicious Domain Pattern Recognition** — Alert on DNS queries containing randomized numeric patterns, especially to domains with non-standard TLDs or suspicious naming conventions like "nip.io"

3. **TXT Record Query Anomalies** — Detect unusual volumes of DNS TXT record requests, as these are commonly used for DNS tunneling and are less frequent in legitimate traffic

4. **PowerShell DNS Cmdlet Monitoring** — Create detections for PowerShell script blocks containing `Resolve-DnsName` cmdlets with suspicious parameters or in loops

5. **DNS Query Entropy Analysis** — Measure hostname entropy in DNS queries to identify algorithmically-generated domain names (high entropy subdomains)

6. **Process-to-DNS Query Correlation** — Monitor for non-browser processes generating high-frequency DNS queries, especially system utilities and scripting hosts

7. **DNS Error Code Pattern Analysis** — Track processes generating consistent DNS query failures (status 9501) which may indicate C2 infrastructure testing

8. **Time-Based DNS Query Clustering** — Detect rapid-fire DNS queries from single processes within short time windows, indicating automated rather than human-driven activity
