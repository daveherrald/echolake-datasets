# T1046-4: Network Service Discovery — Port Scan using python

## Technique Context

T1046 Network Service Discovery involves adversaries scanning for services running on remote hosts to identify potential attack vectors. This technique is fundamental to network reconnaissance, allowing attackers to map available services, identify vulnerable applications, and plan lateral movement. The detection community focuses on unusual network scanning patterns, rapid sequential connections to multiple ports, and the use of non-standard tools or scripts for network enumeration.

This specific test uses Python to perform port scanning against localhost (127.0.0.1), simulating how attackers might use scripting languages to conduct reconnaissance. Python-based port scanning is particularly concerning because it can be customized, evade basic detection, and blend in with legitimate administrative activity.

## What This Dataset Contains

The dataset captures a Python-based port scan executed via PowerShell. Security event 4688 shows the process chain: PowerShell spawns python.exe with the command line `"C:\Program Files\Python312\python.exe" C:\AtomicRedTeam\atomics\T1046\src\T1046.py -i 127.0.0.1`. 

PowerShell event 4104 captures the script block execution: `{python "C:\AtomicRedTeam\atomics\T1046\src\T1046.py" -i 127.0.0.1}`, providing clear evidence of the scanning command.

Sysmon captures the actual network scanning activity through event ID 3 (Network Connection). The python.exe process (PID 2392) generates outbound TCP connections to localhost on ports 3389 (RDP) and 5985 (WinRM), showing `Protocol: tcp`, `Initiated: true`, `SourceIp: 127.0.0.1`, and `DestinationIp: 127.0.0.1`. Corresponding inbound connections are also logged from the listening services.

The dataset includes Sysmon process creation events for both PowerShell (PID 8156) and the python.exe process, with full command-line logging enabled. Process access events (EID 10) show PowerShell accessing both the child processes with `GrantedAccess: 0x1FFFFF`.

## What This Dataset Does Not Contain

The dataset is limited by scanning only localhost (127.0.0.1) rather than remote targets, which reduces the network reconnaissance footprint. The Python script appears to scan only a few specific ports (3389, 5985) rather than performing a comprehensive port sweep, so we don't see the rapid, sequential connection patterns typical of aggressive port scanning.

Missing are Sysmon DNS query events (EID 22) since the scan targets an IP address directly. There are no failed connection attempts visible in the data, suggesting the scan only targeted ports that were actually listening. The dataset lacks any evidence of service enumeration beyond basic connectivity testing.

System event 4227 indicates TCP/IP connection establishment issues due to rapid connection cycling, but this represents only a single instance rather than sustained scanning activity.

## Assessment

This dataset provides good coverage for detecting Python-based network service discovery, particularly through the combination of Security 4688 process creation, PowerShell 4104 script block logging, and Sysmon 3 network connection events. The command-line arguments clearly indicate reconnaissance intent, and the network events show the scanning behavior.

However, the scope is limited to localhost scanning with minimal port coverage, which may not represent real-world attack patterns. The dataset would be stronger with evidence of broader network scanning, failed connection attempts, and scanning of remote hosts. The current data is most useful for detecting the execution method rather than comprehensive scanning behavior.

## Detection Opportunities Present in This Data

1. **Python network scanning process creation** - Security 4688 and Sysmon 1 events showing python.exe execution with suspicious command-line arguments containing IP addresses and scanning-related parameters

2. **PowerShell-initiated Python reconnaissance** - PowerShell 4104 script blocks containing python execution commands with network scanning tools or IP address parameters

3. **Rapid TCP connection patterns from Python processes** - Multiple Sysmon 3 events from python.exe to different ports on the same destination IP within short time windows

4. **Localhost port scanning activity** - Network connections to common administrative ports (3389 RDP, 5985 WinRM) originating from scripting interpreters rather than expected services

5. **Process tree analysis for reconnaissance chains** - Parent-child relationships between PowerShell and python.exe processes where the child performs network connectivity testing

6. **TCP connection exhaustion indicators** - System event 4227 suggesting rapid connection cycling behavior typical of port scanning tools

7. **Python script execution from Atomic Red Team paths** - File path indicators showing execution from known testing frameworks, useful for threat hunting exercises
