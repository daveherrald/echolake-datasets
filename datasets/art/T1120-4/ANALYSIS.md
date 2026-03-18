# T1120-4: Peripheral Device Discovery — Get Printer Device List via PowerShell Command

## Technique Context

T1120 (Peripheral Device Discovery) involves adversaries enumerating connected peripheral devices to understand the target environment's capabilities and potentially identify high-value targets. Printers are particularly interesting to attackers because they often contain cached documents, may have weak security controls, can serve as network pivots, and sometimes store credentials or sensitive configuration data. The `Get-Printer` PowerShell cmdlet is a legitimate administrative tool that retrieves information about installed printers, including their names, status, drivers, and network configurations.

The detection community focuses on monitoring for unusual printer enumeration activities, especially when performed by non-administrative users, from unexpected processes, or in conjunction with other discovery techniques. This technique often appears early in attack chains during initial reconnaissance phases.

## What This Dataset Contains

This dataset captures a PowerShell execution of the `Get-Printer` cmdlet with comprehensive telemetry across multiple data sources. The key evidence includes:

**Process Creation Chain (Security 4688):**
- Parent PowerShell process (PID 29824): `"powershell.exe"`
- Child PowerShell process (PID 36592): `"powershell.exe" & {Get-Printer}`
- Intermediate whoami execution (PID 34176): `"C:\Windows\system32\whoami.exe"`

**PowerShell Script Block Logging (PowerShell 4104):**
- Target script block: `& {Get-Printer}` and `{Get-Printer}`
- Command invocation logging (PowerShell 4103): `Get-Printer` with parameters including `ComputerName=""` and `Full="False"`

**Sysmon Process Creation (Sysmon 1):**
- PowerShell process with full command line: `"powershell.exe" & {Get-Printer}`
- Parent process chain clearly showing the execution hierarchy
- Process access events (Sysmon 10) showing PowerShell accessing both whoami.exe and the child PowerShell process

**Additional Sysmon Evidence:**
- Multiple image load events (Sysmon 7) showing .NET Framework and PowerShell module loading
- Named pipe creation (Sysmon 17) for PowerShell host communication
- File creation events (Sysmon 11) for PowerShell profile data

## What This Dataset Does Not Contain

This dataset does not capture the actual output of the `Get-Printer` command or any network communication that might result from printer discovery. There are no WMI events showing the underlying queries that PowerShell makes to enumerate printers, nor are there any registry access events that might occur during printer enumeration. The dataset also lacks any subsequent actions that might follow printer discovery, such as attempts to access printer shares or query printer configurations in detail.

Notably, the execution runs as NT AUTHORITY\SYSTEM, which may limit the realistic assessment of how this technique would appear when executed by a standard user account with different privileges.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based printer discovery activities. The combination of process creation events with command-line arguments, PowerShell script block logging, and Sysmon's detailed process tracking creates multiple detection opportunities. The Security audit logs provide reliable process creation telemetry that works across different Windows configurations, while PowerShell's native logging captures the exact cmdlet execution with parameters.

The dataset would be stronger if it included the actual printer enumeration results and any associated WMI or registry access patterns. Including execution by a standard user account rather than SYSTEM would also provide more realistic attack telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell Printer Discovery Command Detection**: Monitor PowerShell script block logs (EID 4104) for `Get-Printer` cmdlet execution, especially when used without legitimate administrative context.

2. **Process Command Line Analysis**: Detect Security EID 4688 events where `powershell.exe` executes with command lines containing `Get-Printer` or similar printer enumeration commands.

3. **PowerShell Command Invocation Monitoring**: Alert on PowerShell EID 4103 command invocation events for `Get-Printer` cmdlet, particularly when executed by non-administrative users or outside of expected maintenance windows.

4. **Suspicious Process Chain Detection**: Monitor for PowerShell processes spawning other discovery tools (like whoami) in combination with printer enumeration activities, indicating broader reconnaissance.

5. **Named Pipe Pattern Analysis**: Track Sysmon EID 17 pipe creation events with PowerShell-specific naming patterns when correlated with printer discovery activities.

6. **Privilege Escalation Context**: Correlate printer discovery with Security EID 4703 token right adjustments to identify potential privilege escalation scenarios involving printer access.

7. **PowerShell Module Loading Correlation**: Monitor Sysmon EID 7 image loads of System.Management.Automation components when associated with peripheral discovery commands for more comprehensive detection coverage.
