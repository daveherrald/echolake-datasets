# T1016-7: System Network Configuration Discovery — Qakbot Recon

## Technique Context

T1016 System Network Configuration Discovery involves adversaries gathering information about the victim system's network configuration and settings. This technique is critical for lateral movement planning, understanding network topology, and identifying potential targets or defensive measures. The Qakbot banking trojan, like many sophisticated malware families, performs extensive reconnaissance to map the victim environment before executing its primary objectives.

The detection community focuses on identifying patterns of rapid network discovery commands, especially when executed in sequence from scripting environments. Key indicators include the use of native Windows utilities like `ipconfig`, `arp`, `nslookup`, `netstat`, `route`, and `net` commands with parameters that reveal comprehensive network information rather than routine administrative tasks.

## What This Dataset Contains

This dataset captures a comprehensive Qakbot-style network reconnaissance sequence executed via a batch file (`C:\AtomicRedTeam\atomics\T1016\src\qakbot.bat`). The process chain begins with PowerShell launching `cmd.exe /c "C:\AtomicRedTeam\atomics\T1016\src\qakbot.bat"`, which then executes multiple network discovery tools in sequence:

The Security 4688 events show the complete command-line execution chain:
- `whoami /all` - User context discovery
- `cmd /c set` - Environment variable enumeration  
- `arp -a` - ARP table discovery
- `ipconfig /all` - Network interface configuration
- `net view /all` - Network share discovery (exits with status 0x2, indicating error)
- `nslookup -querytype=ALL -timeout=10 _ldap._tcp.dc._msdcs.WORKGROUP` - Domain controller discovery
- `nslookup -querytype=ALL -timeout=10 _ldap._tcp.dc._msdcs.DomainName` - Additional DC discovery
- `net share` - Local share enumeration
- `route print` - Routing table discovery
- `netstat -nao` - Network connection enumeration
- `net localgroup` - Local group discovery

Sysmon captures the process creation events (EID 1) for these tools, showing parent-child relationships and full command lines. The `nslookup` processes generate DNS queries captured as network connections (EID 3) to the domain DNS server at 192.168.4.10:53. Process access events (EID 10) show PowerShell accessing spawned processes with high privileges (0x1FFFFF access).

## What This Dataset Does Not Contain

The dataset lacks several elements that would be present in a real-world Qakbot infection. There are no DNS query logs (Sysmon EID 22) despite the `nslookup` commands, suggesting either the sysmon-modular configuration doesn't capture DNS events or they were filtered. The `net view /all` command fails (exit code 0x2), so we don't see successful network share discovery results that would typically appear in a domain environment.

Windows Defender is active but doesn't appear to block any of these reconnaissance activities, as they're all legitimate administrative tools being used for information gathering rather than malicious code execution. The PowerShell script block logs contain only test framework boilerplate rather than the actual reconnaissance script content.

## Assessment

This dataset provides excellent coverage for detecting systematic network reconnaissance patterns. The combination of Security 4688 process creation events with full command lines and Sysmon process creation/network connection events creates multiple detection opportunities. The sequential execution of network discovery tools within a short timeframe (14 seconds) represents a clear behavioral pattern that differs significantly from normal administrative activity.

The process relationship data is particularly valuable, showing how a scripting environment launches multiple discovery tools in rapid succession. The command-line arguments captured in Security events provide the specific indicators needed to distinguish reconnaissance from legitimate network troubleshooting.

## Detection Opportunities Present in This Data

1. **Sequential Network Discovery Tool Execution** - Multiple network reconnaissance tools (`ipconfig`, `arp`, `nslookup`, `netstat`, `route`, `net`) executed by the same parent process within a short time window, indicating systematic reconnaissance rather than targeted troubleshooting.

2. **Batch Script Network Reconnaissance** - Detection of batch files containing multiple network discovery commands, identified through the command line `cmd.exe /c` execution pattern with paths to .bat files performing reconnaissance.

3. **DNS Domain Controller Discovery Queries** - `nslookup` commands specifically querying for `_ldap._tcp.dc._msdcs` SRV records, which is a common technique for Active Directory domain controller discovery in reconnaissance phases.

4. **Comprehensive Network Interface Enumeration** - `ipconfig /all` combined with `arp -a` and `route print` executed in sequence, providing complete network topology mapping beyond normal administrative needs.

5. **Privileged Process Chain from PowerShell** - PowerShell spawning cmd.exe which then launches multiple network discovery utilities, with high-privilege process access (0x1FFFFF) indicating potential automation or scripted reconnaissance.

6. **Network Share Discovery Attempts** - `net view` and `net share` commands executed programmatically rather than interactively, especially when combined with other reconnaissance activities.

7. **System Context Discovery with Network Reconnaissance** - `whoami /all` followed immediately by network discovery tools, indicating an adversary gathering both privilege context and network topology information.
