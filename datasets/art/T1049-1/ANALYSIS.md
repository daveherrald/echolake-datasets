# T1049-1: System Network Connections Discovery — System Network Connections Discovery

## Technique Context

T1049 System Network Connections Discovery is a fundamental reconnaissance technique where adversaries enumerate network connections on compromised systems to understand the network topology, identify connected systems, and discover potential lateral movement targets. Attackers commonly use built-in Windows utilities like `netstat`, `net use`, and `net sessions` to gather this intelligence. The detection community focuses on monitoring execution of these network enumeration tools, particularly when executed in rapid succession or from unusual parent processes like PowerShell or scripts, as this often indicates automated reconnaissance rather than legitimate administrative activity.

## What This Dataset Contains

This dataset captures a comprehensive T1049 execution through PowerShell that runs multiple network discovery commands in sequence. The primary evidence appears in Security event 4688 showing the command execution: `"cmd.exe" /c netstat -ano & net use & net sessions 2>nul`. 

The process chain flows from PowerShell (PID 15128) → cmd.exe (PID 15068) → netstat.exe (PID 15864) → net.exe (PID 16332 for "use") → net.exe (PID 15632 for "sessions") → net1.exe (PID 15960). Sysmon EID 1 events capture each process creation with full command lines: `netstat -ano`, `net use`, `net sessions`, and the automatic delegation from net.exe to net1.exe for the sessions command.

Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating process interaction during execution. PowerShell channel events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual reconnaissance commands.

## What This Dataset Does Not Contain

The dataset lacks the actual network enumeration output that these commands would produce - the netstat connections table, mapped network drives from net use, and active SMB sessions from net sessions. This is expected as Windows event logs capture process execution but not stdout/stderr output. 

No network connections (Sysmon EID 3) are present, suggesting the commands ran quickly without establishing new outbound connections for their queries. The sysmon-modular configuration's include-mode ProcessCreate filtering explains why only the specifically-flagged network reconnaissance tools (netstat, net.exe, net1.exe) generated Sysmon EID 1 events while other routine processes did not.

## Assessment

This dataset provides excellent telemetry for detecting T1049 network discovery activities. The combination of Security 4688 events with full command-line logging and Sysmon EID 1 events offers robust coverage of network enumeration tool execution. The process lineage from PowerShell through cmd.exe to the individual reconnaissance utilities creates a clear attack pattern. The rapid succession of netstat, net use, and net sessions commands within seconds strongly indicates automated reconnaissance rather than normal administrative activity.

## Detection Opportunities Present in This Data

1. **Multi-tool network reconnaissance sequence** - Security EID 4688 and Sysmon EID 1 showing netstat.exe, net.exe with "use" and "sessions" parameters executed within a short time window from the same parent process

2. **PowerShell-initiated network discovery** - Process creation events showing network enumeration tools spawned by powershell.exe, particularly when combined in a single command line execution

3. **Net.exe parameter-based detection** - Sysmon EID 1 events capturing net.exe with specific discovery-oriented parameters ("use", "sessions") that indicate network mapping activities

4. **Process access patterns during reconnaissance** - Sysmon EID 10 showing PowerShell accessing spawned reconnaissance processes with full access rights, indicating process management during enumeration

5. **Cmd.exe as reconnaissance launcher** - Security EID 4688 showing cmd.exe with compound commands containing multiple network discovery tools chained with operators (&, &&)
