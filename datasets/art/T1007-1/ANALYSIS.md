# T1007-1: System Service Discovery — System Service Discovery

## Technique Context

System Service Discovery (T1007) involves adversaries gathering information about system services to understand the local environment and identify potential targets. Attackers use this technique during the discovery phase to map running services, their configurations, and dependencies. This intelligence helps them identify vulnerable services, understand the system's purpose, and plan lateral movement or persistence mechanisms.

The detection community focuses on monitoring command-line executions of service enumeration tools like `sc.exe`, `tasklist.exe`, PowerShell cmdlets (Get-Service, Get-WmiObject), and WMI queries targeting service classes. Key indicators include unusual service queries from non-administrative processes, bulk service enumeration, and combinations of discovery techniques executed in sequence.

## What This Dataset Contains

This dataset captures a comprehensive system service discovery sequence executed through PowerShell. The process chain shows:

**PowerShell (PID 3892)** executing a compound command: `"cmd.exe" /c tasklist.exe /svc & sc query & sc query state= all`

**Process Creation Chain (Security 4688 events):**
- `whoami.exe` - User context discovery
- `cmd.exe` - Command shell execution with compound service discovery commands
- `tasklist.exe /svc` - Process enumeration with service mapping
- `sc.exe query` - Active service enumeration  
- `sc.exe query state= all` - All services (including stopped) enumeration

**Sysmon Events:**
- EID 1 captures all process creations with full command lines, including the parent PowerShell process
- EID 7 shows image loads including AMSI.dll and Windows Defender components in tasklist.exe
- EID 10 records process access events from PowerShell to child processes
- EID 17 captures PowerShell named pipe creation

**Command Lines Observed:**
- `"C:\Windows\system32\whoami.exe"`
- `"cmd.exe" /c tasklist.exe /svc & sc query & sc query state= all`
- `tasklist.exe /svc`
- `sc query`
- `sc query state= all`

## What This Dataset Does Not Contain

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks) rather than the actual discovery commands, as these were executed via cmd.exe subprocesses. 

Missing are direct PowerShell-based service discovery methods like `Get-Service` or `Get-WmiObject Win32_Service` cmdlets, which would generate different telemetry patterns. The dataset also lacks any attempt to query remote services or use alternative discovery tools like `wmic service`.

No network-based service discovery (port scanning, banner grabbing) is present, and there are no attempts to access service binaries or configuration files directly.

## Assessment

This dataset provides excellent telemetry for detecting system service discovery activities. The Security 4688 events with command-line logging capture the complete attack sequence, while Sysmon EID 1 events provide additional process ancestry and timing details. The combination of user discovery (`whoami`) followed immediately by comprehensive service enumeration (`tasklist /svc`, `sc query`) represents a classic discovery pattern that detection engineers can reliably identify.

The presence of multiple service enumeration techniques executed in rapid succession through cmd.exe provides clear behavioral indicators. The process access events (Sysmon EID 10) showing PowerShell accessing child processes add additional context for correlation rules.

## Detection Opportunities Present in This Data

1. **Rapid sequence of service discovery commands** - Multiple service enumeration tools (tasklist, sc) executed within seconds through the same parent process

2. **PowerShell spawning cmd.exe with service enumeration** - PowerShell process creating cmd.exe with compound commands containing service discovery tools

3. **Combined user and service discovery** - whoami.exe followed immediately by service enumeration tools from the same parent process

4. **Comprehensive service enumeration pattern** - Use of both `sc query` and `sc query state=all` to enumerate active and inactive services

5. **Process access correlation** - PowerShell process accessing child processes performing discovery activities (Sysmon EID 10)

6. **Service enumeration with service mapping** - tasklist.exe executed with `/svc` parameter to map processes to services

7. **Command shell proxy execution** - PowerShell using cmd.exe to execute multiple discovery commands in a single compound statement
