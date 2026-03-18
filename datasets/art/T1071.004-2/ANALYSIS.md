# T1071.004-2: DNS — DNS Regular Beaconing

## Technique Context

T1071.004 (Application Layer Protocol: DNS) involves adversaries using DNS for command and control communications, often leveraging DNS queries to exfiltrate data, receive commands, or maintain persistence. DNS beaconing is a particularly common variant where malware or implants periodically query DNS servers with encoded information or to check for new instructions. The technique is attractive to attackers because DNS traffic is ubiquitous in enterprise environments and often receives less scrutiny than HTTP/HTTPS traffic.

Detection engineers typically focus on identifying DNS queries to suspicious domains, unusual query patterns (frequency, timing, payload encoding), queries for non-existent domains (NXDOMAIN responses), and DNS queries with suspicious TXT record responses that might contain encoded commands. The community has developed signatures around DNS over HTTPS tunneling, base64-encoded payloads in DNS queries, and beaconing patterns with regular intervals.

## What This Dataset Contains

This dataset captures a PowerShell-based DNS beaconing simulation that executes the script `T1071-dns-beacon.ps1` with parameters targeting `127.0.0.1.nip.io` domain. The Security log shows the PowerShell process creation with the full command line: `"powershell.exe" & {Set-Location \"C:\AtomicRedTeam\atomics\".\T1071.004\src\T1071-dns-beacon.ps1 -Domain 127.0.0.1.nip.io -Subdomain atomicredteam -QueryType TXT -C2Interval 30 -C2Jitter 20 -RunTime 30}`.

The PowerShell channel contains the actual beacon script content showing the DNS query generation logic: `Resolve-DnsName -type $QueryType $Subdomain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout` within a loop structure with timing controls.

Most importantly, Sysmon EID 22 events capture four actual DNS queries performed by the beacon:
- `atomicredteam.416807.127.0.0.1.nip.io` at 18:52:45
- `atomicredteam.26203.127.0.0.1.nip.io` at 18:53:15  
- `atomicredteam.807107.127.0.0.1.nip.io` at 18:53:45
- `atomicredteam.723366.127.0.0.1.nip.io` at 18:54:15

All queries returned QueryStatus 9501 (DNS_ERROR_RCODE_NAME_ERROR/NXDOMAIN) with no results, which is expected since these are test domains. The queries show the randomized subdomain generation pattern with 6-digit random numbers, and the ~30-second intervals match the configured C2Interval parameter.

## What This Dataset Does Not Contain

The dataset lacks DNS queries that would return actual TXT record responses with command data, since this is a benign test execution against non-existent domains. There are no network connection events showing actual C2 communication beyond DNS queries. The test appears to have been limited to a 30-second runtime as configured, so longer-term beaconing patterns aren't captured.

The Sysmon configuration's include-mode filtering means we don't see ProcessCreate events for potential child processes that might be spawned by a real beacon, though the technique execution appears to be entirely PowerShell-based. Windows Defender was active but didn't block this test, likely because it uses legitimate DNS resolution APIs rather than malicious payloads.

## Assessment

This dataset provides excellent telemetry for DNS beaconing detection development. The combination of Security 4688 events with full PowerShell command lines, PowerShell script block logging showing the beacon logic, and Sysmon DNS query events creates a comprehensive detection opportunity matrix. The regular timing intervals, randomized subdomain pattern, and consistent query structure represent realistic DNS C2 behavior patterns.

The data quality is high for building behavioral detections around DNS beaconing frequency, subdomain randomization patterns, and PowerShell-initiated DNS activity. However, the lack of successful DNS responses limits its utility for detecting payload extraction or command retrieval scenarios.

## Detection Opportunities Present in This Data

1. **DNS Query Pattern Analysis** - Detect DNS queries with randomized numeric subdomains using regex patterns against Sysmon EID 22 QueryName fields matching `\w+\.\d{6}\.\d+\.\d+\.\d+\.\d+\.nip\.io`

2. **DNS Beaconing Frequency** - Identify DNS queries from the same process with regular time intervals (approximately 30 seconds) by analyzing Sysmon EID 22 timestamps grouped by ProcessGuid

3. **PowerShell DNS Activity Correlation** - Correlate Security 4688 PowerShell process creation events containing "Resolve-DnsName" parameters with subsequent Sysmon EID 22 DNS queries from the same process

4. **Suspicious Domain Patterns** - Flag DNS queries to domains ending in "nip.io" or other dynamic DNS services commonly used for testing/malicious purposes in Sysmon EID 22 events

5. **Script Block Analysis** - Detect PowerShell script blocks (EID 4104) containing DNS resolution commands combined with random number generation and loop structures indicating automated querying

6. **NXDOMAIN Response Patterns** - Monitor for repeated DNS queries returning QueryStatus 9501 (NXDOMAIN) from the same process, which may indicate C2 infrastructure testing or dead domains

7. **Process Tree Analysis** - Identify PowerShell processes spawning with DNS beaconing scripts by correlating Security 4688 CommandLine fields containing specific DNS parameters (-QueryType, -C2Interval, etc.)
