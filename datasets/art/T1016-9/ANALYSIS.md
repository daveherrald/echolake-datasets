# T1016-9: System Network Configuration Discovery — DNS Server Discovery Using nslookup

## Technique Context

T1016 System Network Configuration Discovery is a fundamental reconnaissance technique where adversaries gather information about network configuration to understand the target environment. The nslookup variant specifically focuses on DNS server discovery, which is particularly valuable in Active Directory environments. Attackers use DNS queries to identify domain controllers, map network infrastructure, and understand the domain structure. The community focuses on detecting unusual nslookup usage patterns, especially queries for AD-specific SRV records like `_ldap._tcp.dc._msdcs` that directly reveal domain controller locations. This technique is commonly seen in post-exploitation phases where attackers are mapping the network before lateral movement.

## What This Dataset Contains

This dataset captures a PowerShell-initiated nslookup command targeting Active Directory service discovery. The core technique evidence appears in Security event 4688 showing the command line: `"cmd.exe" /c nslookup -querytype=ALL -timeout=12 _ldap._tcp.dc._msdcs.%USERDNSDOMAIN%`. The process chain shows PowerShell (PID 7884) spawning cmd.exe (PID 5744), which then launches nslookup.exe (PID 6868) with the specific SRV record query.

Sysmon captures the complete process creation chain with event 1 showing nslookup.exe execution with command line `nslookup -querytype=ALL -timeout=12 _ldap._tcp.dc._msdcs.%%USERDNSDOMAIN%%`. Three Sysmon event 3 network connections show the DNS queries being executed: UDP connections from source IP 192.168.4.12 (the workstation) to 192.168.4.10 (likely the domain controller) on port 53, with different ephemeral source ports (63593, 63594, 63595).

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass commands) and doesn't capture the actual technique execution, as this was likely executed via command-line parameters rather than interactive PowerShell script blocks.

## What This Dataset Does Not Contain

The dataset lacks DNS query logging that would show the actual SRV record requests and responses, which would provide the most direct evidence of the technique. There are no Sysmon event 22 DNS queries despite DNS query logging being enabled, suggesting the sysmon-modular configuration may filter standard DNS lookups. The dataset doesn't include any DNS server logs or network packet captures that would show the query content and responses. Additionally, there's no evidence of the query results or how they might be processed by the attacker, as this was likely output to the console.

## Assessment

This dataset provides solid process-level telemetry for detecting nslookup-based AD reconnaissance but lacks the DNS-specific evidence that would make detection most robust. The Security 4688 events with command-line logging provide the strongest detection opportunity, clearly showing the suspicious nslookup query targeting AD infrastructure. Sysmon process creation and network connection events add valuable context about the execution chain and network activity. However, the absence of DNS query content limits the ability to build comprehensive detections based on the actual queries performed. For production detection engineering, this data would be sufficient for process-based alerts but should ideally be supplemented with DNS query logging.

## Detection Opportunities Present in This Data

1. Security 4688 command-line detection for nslookup execution with AD-specific query types (querytype=ALL) and SRV record patterns (_ldap._tcp.dc._msdcs)

2. Sysmon event 1 process creation monitoring for nslookup.exe with reconnaissance-related command-line arguments, particularly those targeting domain infrastructure

3. Process chain analysis correlating PowerShell spawning cmd.exe, which then executes nslookup with suspicious parameters

4. Sysmon event 3 network connection pattern detection showing multiple rapid UDP connections to port 53 from nslookup processes

5. Parent-child process relationship analysis identifying nslookup launched from scripting environments (PowerShell/cmd) rather than interactive use

6. Command-line pattern matching for environment variable usage in DNS queries (%USERDNSDOMAIN%) combined with AD service discovery queries

7. Behavioral analysis of short-lived nslookup processes with specific timeout parameters suggesting automated rather than manual usage
