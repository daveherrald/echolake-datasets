# T1046-10: Network Service Discovery — Network Service Discovery - Port Scanning /24 Subnet with PowerShell

## Technique Context

Network Service Discovery (T1046) involves adversaries attempting to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. This technique is fundamental to network reconnaissance during the Discovery phase of an attack, allowing adversaries to map out available services, identify potential attack vectors, and understand the network topology.

The specific variant tested here uses PowerShell's `System.Net.Sockets.TcpClient` class to perform TCP connect scans across a /24 subnet, targeting common service ports (445/SMB and 3389/RDP). This approach is stealthy compared to traditional port scanners like Nmap, as it uses legitimate .NET networking APIs and generates minimal suspicious process execution patterns. Detection engineers typically focus on rapid sequential network connections to multiple hosts, unusual PowerShell network activity, and connections to commonly scanned ports.

## What This Dataset Contains

This dataset captures a PowerShell-based subnet scanning operation that successfully executed on the test environment. The primary evidence includes:

**PowerShell Script Block Logging (EID 4104)**: The complete port scanning script is captured, showing the logic for subnet enumeration: `$subnetIPs = 1..254 | ForEach-Object { "$subnetSubstring$_" }` and TCP connection attempts using `New-Object Net.Sockets.TcpClient` and `$tcp.ConnectAsync($ip, $port).Wait(200)`.

**Network Connections (Sysmon EID 3)**: Multiple TCP connection attempts are logged, including successful connections to 192.168.4.10:445 and several other IPs on ports 445 and 3389. The timestamps show sequential scanning behavior with connections occurring between 17:48:11 and 17:48:15.

**Process Creation (Security EID 4688, Sysmon EID 1)**: Shows the spawning of PowerShell processes (PID 23632, 23832) with the complete command line containing the embedded scanning script.

**PowerShell Command Invocation (EID 4103)**: Detailed logging of PowerShell cmdlet execution including `Get-NetIPInterface`, `Get-NetIPAddress`, `New-Object`, and `Write-Host` calls, providing granular visibility into the scanning methodology.

The script successfully identified at least one open port (445 on 192.168.4.10) as evidenced by the PowerShell command invocation: `Write-Host "Port 445 is open on 192.168.4.10"`.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide a complete picture of network scanning activity:

**DNS Resolution Activity**: No DNS queries are captured in Sysmon, suggesting the script operated purely with IP addresses rather than attempting hostname resolution.

**ICMP Activity**: The scanning technique only uses TCP connections, so no ICMP ping sweeps or other network discovery methods are present.

**Firewall Logs**: Windows Firewall events that might show blocked connection attempts to non-responsive hosts are not included in this dataset.

**Complete Scan Results**: While we see evidence of successful connections to some hosts, the full scope of which hosts responded or failed is not comprehensively captured in the logs.

**Persistence Mechanisms**: The script appears to be a one-time execution without any persistence establishment or follow-up reconnaissance activities.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based network scanning activities. The combination of PowerShell script block logging (4104) and Sysmon network connection monitoring (EID 3) creates a comprehensive detection surface. The Security audit policy capturing process creation with command-line arguments provides additional context that would survive even if PowerShell logging were disabled.

The data quality is particularly strong for behavioral detection approaches - the rapid sequential network connections to multiple hosts within the same subnet, combined with PowerShell's network object instantiation patterns, create clear behavioral signatures. The 200ms timeout specified in the script (`Wait(200)`) and the systematic IP iteration provide timing and pattern characteristics that would be difficult for an attacker to obfuscate without significantly slowing their reconnaissance.

The main limitation is the relatively small scope of the scan captured - only a few successful connections are logged, which may represent either a small test network or incomplete logging of failed connection attempts.

## Detection Opportunities Present in This Data

1. **PowerShell Network Object Creation Pattern**: Alert on PowerShell processes creating multiple `System.Net.Sockets.TcpClient` objects within short time windows, particularly when combined with `ConnectAsync` method calls.

2. **Rapid Sequential Network Connections**: Detect single processes making TCP connections to multiple unique IP addresses within the same subnet (e.g., >10 unique IPs in <5 minutes).

3. **PowerShell Script Block Content Analysis**: Hunt for PowerShell scripts containing subnet enumeration patterns like `1..254 | ForEach-Object` combined with network connection code.

4. **Common Port Scanning Signatures**: Monitor for connections to typical reconnaissance ports (22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080) from single source processes.

5. **PowerShell Process Network Behavior Baseline**: Establish baselines for normal PowerShell network activity and alert on deviations, particularly PowerShell processes making connections to multiple hosts.

6. **Cross-Log Correlation**: Correlate PowerShell script block events (4104) containing network-related cmdlets with corresponding Sysmon network connections (EID 3) from the same process.

7. **Subnet Enumeration Command Line Detection**: Alert on process creation events containing embedded PowerShell scripts with network scanning characteristics, particularly those with IP range generation logic.
