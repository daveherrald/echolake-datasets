# T1135-4: Network Share Discovery — Network Share Discovery command prompt

## Technique Context

T1135 Network Share Discovery is a fundamental reconnaissance technique where adversaries enumerate network shares accessible from a compromised system. This technique is crucial for lateral movement and data discovery phases, as shared folders often contain sensitive information or provide pathways to other systems. Attackers commonly use built-in Windows utilities like `net view`, `net share`, or PowerShell cmdlets to identify available shares on local and remote systems. The detection community focuses on monitoring process creation events for these native utilities, especially when executed with suspicious arguments targeting specific hosts or using wildcard patterns for broad enumeration.

## What This Dataset Contains

This dataset captures a classic network share enumeration attempt using the Windows `net view` command. The key telemetry shows:

**Process Creation Chain (Security 4688 events):**
- PowerShell spawning cmd.exe: `"cmd.exe" /c net view \\localhost`
- cmd.exe spawning net.exe: `net view \\localhost`

**Sysmon Process Creation (EID 1):**
- whoami.exe execution: `"C:\Windows\system32\whoami.exe"`
- cmd.exe with share discovery: `"cmd.exe" /c net view \\localhost`
- net.exe with target specification: `net view \\localhost`

**Process Access Events (Sysmon EID 10):**
PowerShell accessing both spawned processes with full access (0x1FFFFF), indicating process monitoring/control.

**Exit Status Telemetry (Security 4689):**
The net.exe process exits with status 0x2, suggesting the command failed or encountered an error, which is typical when querying shares on localhost without administrative shares enabled.

## What This Dataset Does Not Contain

The dataset lacks network-level telemetry that would show actual SMB connections or authentication attempts. There are no DNS queries (Sysmon EID 22) for hostname resolution since `\\localhost` doesn't require DNS lookup. The technique appears to have failed based on the exit code 0x2, so there's no successful share enumeration output or follow-up file access attempts. Additionally, there are no registry modifications or credential access events that might accompany more sophisticated share discovery techniques.

## Assessment

This dataset provides excellent baseline telemetry for detecting network share discovery attempts using native Windows utilities. The Security 4688 events with command-line logging offer the most reliable detection opportunity, capturing the exact commands used. Sysmon EID 1 events complement this with additional process metadata and parent-child relationships. The combination of process creation, command-line arguments, and exit status provides a complete picture of the technique execution, even when it fails. This data would be highly valuable for detection rule development and threat hunting scenarios.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** on Security 4688 events for `net view` commands with UNC path arguments like `\\localhost` or specific hostnames
2. **Process creation monitoring** for net.exe spawned from cmd.exe or PowerShell with "view" argument in Sysmon EID 1 events
3. **Parent-child process relationships** identifying cmd.exe → net.exe chains initiated by scripting engines
4. **Process access events** detecting PowerShell or other processes opening handles to net.exe with full access rights (0x1FFFFF)
5. **Failed execution correlation** combining process creation with exit code 0x2 to identify unsuccessful but suspicious reconnaissance attempts
6. **Execution context analysis** flagging net.exe execution from system profiles or service accounts that typically don't perform interactive network discovery
