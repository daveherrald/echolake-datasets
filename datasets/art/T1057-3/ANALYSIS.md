# T1057-3: Process Discovery — Process Discovery - Get-Process

## Technique Context

Process Discovery (T1057) is a foundational discovery technique where adversaries enumerate running processes to understand system state, identify security tools, and locate potential targets for further exploitation. The `Get-Process` PowerShell cmdlet is a legitimate administrative tool that provides comprehensive process information including process names, IDs, CPU usage, memory consumption, and associated services. Attackers commonly use this cmdlet early in the attack lifecycle for situational awareness, security tool identification, and target selection. Detection engineers focus on identifying suspicious PowerShell execution patterns, especially when combined with other discovery techniques or executed from unusual parent processes.

## What This Dataset Contains

This dataset captures a straightforward execution of `Get-Process` via PowerShell with excellent telemetry coverage:

**Process Chain Evidence:**
- Security 4688: Parent PowerShell process (PID 41436) spawning child PowerShell with command line `"powershell.exe" & {Get-Process}`
- Sysmon EID 1: Child PowerShell process creation (PID 44532) with full command line `"powershell.exe" & {Get-Process}`
- Security 4688: Whoami.exe execution (PID 44980) with command line `"C:\Windows\system32\whoami.exe"`

**PowerShell Execution Evidence:**
- PowerShell EID 4103: CommandInvocation showing `Get-Process` cmdlet execution with context details
- PowerShell EID 4104: Script block creation for `& {Get-Process}` and `{Get-Process}` showing the actual command structure
- PowerShell EID 4104: Multiple test framework-related script blocks for error handling and execution policy bypass

**System Interaction Evidence:**
- Sysmon EID 10: Process access events showing PowerShell accessing both whoami.exe (0x1FFFFF access) and the child PowerShell process
- Sysmon EID 7: .NET runtime and PowerShell module loading in both PowerShell processes
- Sysmon EID 17: Named pipe creation for PowerShell host communication
- Security 4703: Token privilege adjustment showing elevation of multiple high-privilege tokens

## What This Dataset Does Not Contain

The dataset lacks the actual output from `Get-Process` since Windows event logs don't capture stdout/stderr from legitimate commands. There are no network connections, file writes containing process lists, or registry modifications that would indicate data exfiltration. The Sysmon configuration's include-mode filtering means we don't see all child processes that might have been enumerated by `Get-Process`, only those matching suspicious patterns (like whoami.exe). There's no evidence of subsequent malicious activity that would typically follow process discovery in a real attack scenario.

## Assessment

This dataset provides excellent detection coverage for PowerShell-based process discovery. The combination of Security 4688 command-line logging, Sysmon process creation events, and PowerShell operational logs creates comprehensive visibility into the execution. The presence of process access events (Sysmon EID 10) adds valuable context about how PowerShell interacts with discovered processes. While the technique itself is benign, the telemetry quality makes this dataset valuable for baseline establishment and detection rule development. The main limitation is the lack of output capture, but this is expected for standard Windows logging.

## Detection Opportunities Present in This Data

1. **PowerShell Process Discovery Command Execution** - PowerShell EID 4103 CommandInvocation events for `Get-Process` cmdlet with process context
2. **Suspicious PowerShell Command Lines** - Security 4688/Sysmon EID 1 capturing `"powershell.exe" & {Get-Process}` execution pattern
3. **PowerShell Script Block Analysis** - PowerShell EID 4104 script blocks containing `Get-Process` cmdlet execution
4. **Process Access Pattern Detection** - Sysmon EID 10 showing PowerShell accessing multiple processes with full access rights (0x1FFFFF)
5. **Discovery Technique Chaining** - Correlation between `Get-Process` and `whoami.exe` execution suggesting reconnaissance activity
6. **High-Privilege PowerShell Execution** - Security 4703 token privilege adjustment showing extensive system privileges being enabled
7. **Named Pipe Communication Monitoring** - Sysmon EID 17 PowerShell host pipe creation indicating active PowerShell sessions
