# T1016.001-3: Internet Connection Discovery — Check internet connection using Test-NetConnection in PowerShell (ICMP-Ping)

## Technique Context

T1016.001 Internet Connection Discovery is a discovery technique where adversaries determine internet connectivity to validate command and control infrastructure access, assess network defenses, and plan data exfiltration routes. Unlike general network discovery, this specifically focuses on testing external internet reachability. Attackers commonly use built-in utilities like `ping`, `Test-NetConnection`, `nslookup`, or even simple HTTP requests to well-known services (8.8.8.8, google.com, etc.). The detection community focuses on identifying automated or scripted connectivity tests, especially to suspicious destinations, unusual timing patterns, or from processes that don't typically perform network operations.

## What This Dataset Contains

This dataset captures a PowerShell-based internet connectivity test using `Test-NetConnection -ComputerName 8.8.8.8`. The execution chain shows:

**Process Creation Chain (Security 4688):**
- Parent PowerShell process spawns child: `"powershell.exe" & {Test-NetConnection -ComputerName 8.8.8.8}`
- Whoami execution: `"C:\Windows\system32\whoami.exe"` for system identification

**PowerShell Activity (4103/4104):**
- Script block creation: `& {Test-NetConnection -ComputerName 8.8.8.8}`
- Detailed command invocations including `ResolveTargetName`, `PingTest`, `Write-Progress` with "Ping/ICMP Test" status
- DNS resolution attempts: `Resolve-DnsName` calls with parameters like `-DnsOnly`, `-NoHostsFile`, `-Type A_AAAA`
- Network security and routing analysis: `Find-NetIPsecRule`, `Find-NetRoute`, `Get-NetAdapter` calls
- CIM method invocation: `Invoke-CimMethod` against `MSFT_NetAddressFilter` class for isolation type queries

**Sysmon Process/Network Evidence:**
- Process creation (EID 1) for whoami.exe and child PowerShell with full command line visibility
- Process access (EID 10) events showing PowerShell accessing whoami and child PowerShell processes
- .NET runtime and PowerShell module loads (EID 7) including `System.Management.Automation.ni.dll`
- Named pipe creation (EID 17) for PowerShell host communication
- Sysmon network connections (EID 3) showing mDNS traffic on port 5353, but notably missing the actual ICMP ping to 8.8.8.8

## What This Dataset Does Not Contain

**Missing ICMP Traffic:** The dataset lacks Sysmon EID 3 network connection events showing the actual ICMP ping to 8.8.8.8. This is expected since Sysmon's NetworkConnect only captures TCP/UDP connections, not ICMP packets. The Test-NetConnection ping functionality doesn't generate TCP/UDP traffic that Sysmon would log.

**Limited DNS Query Evidence:** While PowerShell logs show DNS resolution attempts, there are no Sysmon EID 22 DNS query events. The sysmon-modular configuration may not have DNS logging enabled, or the DNS queries may have been filtered.

**No TCP Port Test:** The Test-NetConnection execution shown here only performs ICMP ping testing. TCP port connectivity tests (which would generate Sysmon EID 3 events) are not present in this specific execution.

**Missing Network Adapter Details:** While PowerShell shows `Get-NetAdapter` calls, the actual network interface enumeration results aren't captured in the telemetry.

## Assessment

This dataset provides excellent PowerShell behavioral evidence for internet connectivity testing but limited network-level visibility. The PowerShell channel captures the complete Test-NetConnection execution flow with detailed command invocations and parameters, making it valuable for detecting scripted connectivity tests. Security event logs provide clean process creation chains. However, the lack of actual network traffic evidence (ICMP pings) means you cannot definitively confirm successful internet connectivity from network logs alone. For comprehensive detection of this technique, you would need additional network monitoring (packet capture, firewall logs, or DNS logs) beyond standard Windows telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell Test-NetConnection Usage** - Monitor PowerShell EID 4103 CommandInvocation events for `Test-NetConnection` with external IP addresses like 8.8.8.8, especially from system or service accounts.

2. **Internet Connectivity Test Script Blocks** - Detect PowerShell EID 4104 script block creation containing `Test-NetConnection -ComputerName` followed by public DNS servers or well-known internet hosts.

3. **Automated Network Discovery Patterns** - Look for rapid sequential PowerShell network commands: `ResolveTargetName`, `PingTest`, `Resolve-DnsName`, `Find-NetRoute` within short time windows.

4. **Suspicious DNS Resolution Attempts** - Monitor PowerShell calls to `Resolve-DnsName` with parameters like `-DnsOnly`, `-NoHostsFile` targeting external IP addresses rather than domain names.

5. **System Account Network Testing** - Flag Test-NetConnection execution by NT AUTHORITY\SYSTEM or other service accounts, as legitimate admin tools rarely perform internet connectivity tests from these contexts.

6. **CIM Network Security Queries** - Detect `Invoke-CimMethod` calls against `MSFT_NetAddressFilter` or network-related WMI classes, which may indicate network reconnaissance beyond simple connectivity testing.

7. **Process Chain Anomalies** - Monitor for PowerShell spawning child PowerShell processes with network testing commands, especially when the parent process lacks clear administrative context.
