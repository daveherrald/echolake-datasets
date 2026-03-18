# T1124-1: System Time Discovery — System Time Discovery

## Technique Context

System Time Discovery (T1124) involves adversaries gathering information about the system's current time and time zone settings. This technique is commonly used during the reconnaissance phase of an attack to understand the target environment's temporal characteristics, which can inform timing-based attacks, help correlate events across systems, or provide context for further operations. Attackers often use built-in Windows utilities like `net time`, `w32tm`, or PowerShell cmdlets to retrieve time information from local or remote systems.

The detection community focuses on monitoring command-line executions of time-related utilities, particularly when used with network parameters (like `\\localhost` or remote hostnames), as these patterns often indicate reconnaissance activities rather than legitimate system administration.

## What This Dataset Contains

This dataset captures a complete execution of the Atomic Red Team T1124-1 test, which executes the command `net time \\localhost & w32tm /tz` through PowerShell. The telemetry shows:

**Process Creation Chain (Security 4688 events):**
- PowerShell process (PID 7704) spawning cmd.exe with command line `"cmd.exe" /c net time \\localhost & w32tm /tz`
- cmd.exe (PID 19064) launching net.exe with `net time \\localhost`
- net.exe (PID 32748) spawning net1.exe with `C:\Windows\system32\net1 time \\localhost`
- cmd.exe also launching w32tm.exe with `w32tm /tz`

**Sysmon Process Creation Events (EID 1):**
- whoami.exe execution (PID 39372) with rule match for T1033 (System Owner/User Discovery)
- cmd.exe execution (PID 19064) with rule match for T1059.003 (Windows Command Shell)
- net.exe execution (PID 32748) with rule match for T1018 (Remote System Discovery)
- net1.exe execution (PID 42060) with rule match for T1018 (Remote System Discovery)

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe processes with full access (0x1FFFFF), indicating process monitoring/injection detection patterns

**Exit Status Information:**
- net1.exe and net.exe both exit with status 0x2 (error condition)
- w32tm.exe exits successfully with status 0x0

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide complete visibility:

- **Network connection telemetry** for the `net time \\localhost` command, which should generate network activity to the local system
- **Process creation events** for the initial PowerShell test framework process due to sysmon-modular's include-mode filtering
- **Command output capture** showing the actual time information retrieved by the commands
- **DNS resolution events** that might occur during hostname resolution for localhost
- **Registry access patterns** that w32tm might use when querying time zone information

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual time discovery commands, as those were executed through cmd.exe rather than directly in PowerShell.

## Assessment

This dataset provides excellent coverage of the process execution aspects of system time discovery techniques. The Security audit logs capture complete command-line information for all processes in the chain, while Sysmon adds valuable process relationship data and behavioral context through its rule matching. The combination of both data sources creates redundant but complementary coverage that would be difficult to evade.

The process access events from Sysmon EID 10 are particularly valuable as they may indicate PowerShell's monitoring or interaction with the spawned processes. However, the lack of network telemetry and command output data limits the ability to detect more sophisticated time discovery techniques that might use alternative methods or remote targets.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** on Security 4688 events for `net time` commands, especially with UNC paths or remote hostnames
2. **Process chain analysis** detecting cmd.exe spawning net.exe/net1.exe in rapid succession with time-related arguments
3. **Parent-child relationship monitoring** for PowerShell processes launching command shells that execute time discovery utilities
4. **Multiple time utility execution** within short time windows (net time + w32tm combination pattern)
5. **Sysmon rule correlation** leveraging the T1018 Remote System Discovery detections triggered by net.exe executions
6. **Process access pattern analysis** for PowerShell processes accessing multiple child processes with full permissions
7. **Exit code monitoring** for net.exe/net1.exe error conditions that might indicate reconnaissance attempts against non-responsive targets
8. **Time utility clustering** detecting multiple different time-related commands executed by the same parent process or session
