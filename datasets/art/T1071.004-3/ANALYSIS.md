# T1071.004-3: DNS — DNS Long Domain Query

## Technique Context

T1071.004 (Application Layer Protocol: DNS) represents one of the most fundamental command and control techniques used by adversaries. DNS traffic is ubiquitous in enterprise environments and rarely blocked, making it an attractive channel for data exfiltration and C2 communications. This specific test focuses on DNS long domain queries — an evasion technique where attackers generate unusually long domain names to bypass basic detection rules that only examine short queries.

The detection community typically focuses on DNS query length anomalies, suspicious domain patterns, query frequency, and non-standard record types. Long domain queries can be used for DNS tunneling, where data is encoded in subdomain names, or for domain generation algorithms (DGAs) that create predictable but complex domain patterns. This technique is particularly relevant for detecting advanced persistent threats that use DNS as a covert channel.

## What This Dataset Contains

This dataset captures a PowerShell script systematically generating DNS TXT queries with progressively longer domain names. The core evidence appears in Security event 4688 showing the PowerShell execution with the full command line:

`"powershell.exe" & {Set-Location \"C:\AtomicRedTeam\atomics\".\T1071.004\src\T1071-dns-domain-length.ps1 -Domain 127.0.0.1.nip.io -Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte -QueryType TXT}`

PowerShell event 4104 captures the complete script content showing the domain length generation logic: the script systematically constructs domains from length 28 to 253 characters using the pattern `[length].[subdomain1].[subdomain2].[subdomain3].[subdomain4].127.0.0.1.nip.io`.

The Sysmon EID 22 events provide the most valuable detection data — 196 DNS queries ranging from simple queries like `028.a.a.a.a.127.0.0.1.nip.io` to extremely long domains like `253.atomicredteamatomicredteamatomicredteamatomicredteamatomicredte.atomicredteamatomicredteamatomicredteamatomicredteamatomicredte.atomicredteamatomicredteamatomicredteamatomicredteamatomicredte.atomicredteamatomicredteamatomicredteamatomicredteamatomicredte.127.0.0.1.nip.io`. All queries show QueryStatus 9501 (DNS_ERROR_RCODE_NAME_ERROR), indicating the domains don't exist.

## What This Dataset Does Not Contain

The dataset lacks any actual DNS responses since the queries target non-existent domains. There are no network connection events (Sysmon EID 3) showing the DNS traffic leaving the host, which limits visibility into the network-level behavior. The sysmon-modular configuration's include-mode filtering means we don't see the initial PowerShell process creation event, though Security 4688 captures the command line.

The test doesn't demonstrate successful DNS tunneling with actual data exfiltration, nor does it show realistic C2 communication patterns. Windows DNS Client service logs aren't captured, which would provide additional context about DNS resolution behavior. No failed connection attempts or DNS server responses are visible in the dataset.

## Assessment

This dataset provides excellent visibility into DNS-based command and control techniques from a host perspective. The Sysmon EID 22 DNS query events are particularly valuable, capturing the complete domain names, query types, and response codes — exactly what detection engineers need for building DNS anomaly detection rules. The PowerShell script content in EID 4104 offers insight into the technique's implementation.

The Security 4688 events provide crucial process context, showing how the technique is launched and what parameters are used. The combination of command-line visibility, script content, and DNS query details creates a comprehensive picture of the attack technique. The systematic progression from short to long domain names makes this an ideal dataset for testing length-based detection thresholds.

However, the lack of network-level DNS traffic and successful resolutions limits its utility for testing network-based detection rules. The artificial nature of the test domains also means it won't help with detecting real-world DGA patterns or legitimate tunneling protocols.

## Detection Opportunities Present in This Data

1. **DNS Query Length Anomaly Detection**: Alert on DNS queries exceeding typical thresholds (e.g., >100 characters total domain length) using Sysmon EID 22 QueryName field analysis.

2. **Progressive Domain Length Patterns**: Detect systematically increasing domain lengths from the same process, indicating automated DNS testing or tunneling setup.

3. **High-Frequency DNS Queries from PowerShell**: Monitor for PowerShell processes generating excessive DNS queries (>50 queries in short timeframes) using process correlation.

4. **TXT Record Query Anomalies**: Flag unusual TXT record queries, especially from scripting processes, as these are commonly used for DNS tunneling.

5. **Failed DNS Resolution Patterns**: Alert on processes generating large numbers of NXDOMAIN responses (QueryStatus 9501), potentially indicating DGA activity or tunneling attempts.

6. **Command Line Pattern Matching**: Detect PowerShell executions with DNS-related parameters like "-Domain", "-QueryType", and long subdomain arguments in Security EID 4688.

7. **Subdomain Structure Analysis**: Identify domains with repetitive subdomain patterns (like "atomicredteam" repeated multiple times) that may indicate data encoding.

8. **Process-DNS Query Correlation**: Build behavioral profiles linking specific processes to their DNS query patterns to identify anomalous DNS usage by legitimate processes.
