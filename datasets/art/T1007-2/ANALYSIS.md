# T1007-2: System Service Discovery — System Service Discovery - net.exe

## Technique Context

T1007 (System Service Discovery) involves adversaries enumerating services running on compromised systems to understand the environment, identify security tools, find persistence mechanisms, or discover lateral movement opportunities. The `net.exe start` command is one of the most common legitimate Windows utilities used for this purpose, making it a frequently observed technique in both legitimate administration and malicious reconnaissance.

Detection engineers focus on monitoring service enumeration commands, particularly when executed in suspicious contexts like from PowerShell, unusual parent processes, or in combination with other discovery techniques. The challenge lies in distinguishing legitimate administrative activity from malicious reconnaissance, often requiring behavioral analysis and broader attack context.

## What This Dataset Contains

This dataset captures a straightforward execution of `net.exe start` to enumerate running services. The key telemetry includes:

**Process Chain (Security 4688 events):**
- PowerShell (PID 6708) → cmd.exe (PID 4864) → net.exe (PID 1592) → net1.exe (PID 6452)
- Command line: `"cmd.exe" /c net.exe start >> %temp%\service-list.txt`
- Full net.exe command: `net.exe start`

**Sysmon Process Creation (EID 1):**
- Multiple processes captured including whoami.exe, cmd.exe, net.exe, and net1.exe executions
- Clear parent-child relationships showing PowerShell spawning the reconnaissance chain
- All processes running as NT AUTHORITY\SYSTEM

**File Operations (Sysmon EID 11):**
- Creation of `C:\Windows\Temp\service-list.txt` by cmd.exe process
- This file would contain the output of the service enumeration command

**PowerShell Activity:**
- Only test framework boilerplate visible (Set-ExecutionPolicy Bypass calls)
- No actual technique-specific PowerShell script block logging

## What This Dataset Does Not Contain

The dataset is missing several elements that would provide a complete picture:
- The actual content of the service-list.txt file that was created
- Network activity that might indicate data exfiltration of discovered services
- Registry queries that might accompany service discovery
- Additional reconnaissance commands that typically follow service enumeration
- Any evidence of the attacker's reaction to discovered services

The PowerShell logging contains only test framework setup commands rather than the actual technique execution logic, which appears to have been handled through direct process execution rather than PowerShell cmdlets.

## Assessment

This dataset provides solid foundational telemetry for detecting basic service discovery using net.exe. The process creation events in both Security and Sysmon channels offer reliable detection opportunities, and the file creation provides evidence of output redirection. However, the technique execution is quite straightforward and doesn't demonstrate more sophisticated evasion techniques or variations that defenders commonly encounter.

The telemetry quality is good for building basic detection rules but limited for understanding advanced adversary tradecraft or developing behavioral analytics that account for legitimate administrative use cases.

## Detection Opportunities Present in This Data

1. **Process chain analysis** - PowerShell spawning cmd.exe which executes net.exe start, detectable via Security 4688 or Sysmon EID 1 parent-child relationships

2. **Command line pattern matching** - The specific command `net.exe start` in Security 4688 or Sysmon EID 1 CommandLine fields

3. **File creation in temp directories** - Sysmon EID 11 showing creation of service-list.txt in %temp%, indicating output redirection of reconnaissance commands

4. **Net utility execution** - Both net.exe and net1.exe process creation events, where net.exe typically spawns net1.exe as the actual implementation

5. **Privilege escalation context** - All processes running as NT AUTHORITY\SYSTEM, which may indicate prior compromise or legitimate administrative activity requiring additional context

6. **Process access events** - Sysmon EID 10 showing PowerShell accessing spawned child processes, which could indicate process injection or monitoring techniques

7. **Behavioral clustering** - Combination of whoami.exe and net.exe start execution in short timeframe, indicating reconnaissance phase activity
