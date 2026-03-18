# T1016-1: System Network Configuration Discovery — System Network Configuration Discovery on Windows

## Technique Context

T1016 System Network Configuration Discovery represents one of the most fundamental discovery techniques in the MITRE ATT&CK framework. Attackers use this technique to gather information about network configurations, interfaces, routing tables, and connectivity details that help them understand the target environment and plan lateral movement. This technique is particularly valuable during the early stages of an attack when adversaries need to map network topology and identify potential pivot points.

Common tools and commands associated with this technique include `ipconfig`, `netsh`, `arp`, `nbtstat`, and `net` commands on Windows systems. Detection teams typically focus on monitoring for rapid succession of these network discovery commands, especially when executed from unusual processes or contexts, as legitimate system administration rarely requires all these commands executed together in quick succession.

## What This Dataset Contains

This dataset captures a comprehensive network discovery sequence executed via PowerShell. The attack chain begins with two PowerShell processes (PIDs 8052 and 8068) spawning from the Atomic Red Team test framework. The core network discovery activity occurs through a cmd.exe process (PID 7196) with the command line:

`"cmd.exe" /c ipconfig /all & netsh interface show interface & arp -a & nbtstat -n & net config`

Security event 4688 shows the complete process tree:
- PowerShell spawns cmd.exe (PID 7196)
- cmd.exe sequentially executes ipconfig.exe (PID 6388) with `/all` flag
- netsh.exe (PID 7236) with `interface show interface`
- ARP.EXE (PID 2848) with `-a` flag  
- nbtstat.exe (PID 2848) with `-n` flag
- net.exe (PID 4460) which spawns net1.exe (PID 5492) for `config`

Sysmon provides detailed process creation events (EID 1) with comprehensive metadata including file hashes, command lines, and parent-child relationships. The events show the technique mapped correctly with RuleName annotations like `technique_id=T1016,technique_name=System Network Configuration Discovery` for ipconfig and nbtstat, and related discovery techniques for other tools.

Process access events (Sysmon EID 10) capture PowerShell accessing child processes with full access rights (0x1FFFFF), indicating process monitoring or control behavior. Named pipe creation events (EID 17) show PowerShell establishing communication channels typical of process orchestration.

## What This Dataset Does Not Contain

The dataset lacks the actual command output that would reveal the discovered network information - we see process execution telemetry but not what the commands returned. There are no network connection events (Sysmon EID 3) showing potential follow-up activities based on the discovered network configuration.

File creation events are minimal, showing only PowerShell profile data writes. Registry access events are absent, so we cannot see if the tools accessed network configuration registry keys. DNS query events (Sysmon EID 22) are not present, indicating the commands didn't trigger DNS lookups during this execution.

The PowerShell script block logging (EID 4104) contains only test framework boilerplate - Set-StrictMode calls and error handling templates - rather than the actual network discovery commands, suggesting the discovery was executed through direct process creation rather than PowerShell cmdlets.

## Assessment

This dataset provides excellent telemetry for detecting T1016 System Network Configuration Discovery through process-based detection methods. The Security audit policy with command-line logging delivers complete visibility into the attack chain, while Sysmon's include-mode filtering appropriately captures all the network discovery tools as they match known-suspicious patterns.

The combination of Security 4688 events with full command lines and Sysmon 1 events with detailed process metadata gives detection engineers rich data sources for building robust rules. The clear parent-child process relationships and timing patterns make this dataset particularly valuable for developing behavioral analytics focused on rapid succession network discovery activities.

The main limitation is the absence of command output data, which reduces its value for threat hunting scenarios where analysts need to understand what information was actually discovered.

## Detection Opportunities Present in This Data

1. **Rapid succession network discovery command sequence** - Multiple network discovery tools (ipconfig, netsh, arp, nbtstat, net) executed within seconds from the same parent process

2. **PowerShell spawning network reconnaissance tools** - PowerShell process creating cmd.exe that executes network discovery commands, unusual for legitimate PowerShell usage

3. **Comprehensive network discovery pattern** - Execution of ipconfig /all, netsh interface commands, arp -a, nbtstat -n, and net config in sequence indicating systematic network enumeration

4. **Process access pattern for discovery orchestration** - PowerShell accessing spawned network tool processes with full access rights (0x1FFFFF) suggesting programmatic control

5. **Named pipe creation during discovery** - PowerShell creating named pipes concurrent with network tool execution, indicating process communication/control mechanisms

6. **Network tool execution from temporary directory** - Network discovery commands executing from C:\Windows\Temp\ rather than standard user directories

7. **SYSTEM context network discovery** - Network enumeration tools running under NT AUTHORITY\SYSTEM indicating privileged discovery activity

8. **Net.exe spawning net1.exe pattern** - Detection of the characteristic net.exe → net1.exe process relationship during network configuration queries
