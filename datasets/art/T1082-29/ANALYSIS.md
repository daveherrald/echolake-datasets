# T1082-29: System Information Discovery — Check computer location

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries gather information about the target system's configuration, installed software, hardware, and other environmental details. This specific test focuses on discovering the computer's geographic location configuration through registry queries. Attackers use this information to understand their target environment, determine if they're in a sandbox or research environment, and tailor subsequent attacks based on the system's characteristics.

The geographic location discovery variant is particularly relevant for adversaries conducting targeted attacks, as it helps determine if they've compromised their intended target or landed in an unexpected environment. Defense teams commonly monitor for registry queries to location-related keys as they're uncommon in normal operations but frequently used in malware and reconnaissance tools.

## What This Dataset Contains

This dataset captures a PowerShell-based system information discovery attempt that queries geographic location settings via registry access. The core activity involves:

**Process Chain:**
- PowerShell (PID 37332) → cmd.exe (PID 37364) → reg.exe (PID 38496)

**Key Commands Captured:**
- Security EID 4688: `"cmd.exe" /c reg query "HKEY_CURRENT_USER\Control Panel\International\Geo"`
- Security EID 4688: `reg query "HKEY_CURRENT_USER\Control Panel\International\Geo"`

**Sysmon Events:**
- EID 1 process creation for whoami.exe, cmd.exe, and reg.exe with full command lines
- EID 10 process access events showing PowerShell accessing child processes with 0x1FFFFF permissions
- EID 7 image loads for .NET runtime components in PowerShell processes
- EID 17 named pipe creation for PowerShell host communication

**Registry Query Activity:**
The reg.exe execution targets `HKEY_CURRENT_USER\Control Panel\International\Geo`, which contains Windows geographic location settings including country codes and regional information.

## What This Dataset Does Not Contain

This dataset lacks several elements that would provide a complete picture of system information discovery:

**Missing Registry Query Results:** While we see the reg.exe process creation and command line, the actual registry query output and results are not captured in any event logs. The Sysmon configuration doesn't include registry access monitoring (EID 12/13).

**Limited PowerShell Script Content:** The PowerShell channel contains only framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual discovery commands or scripts being executed.

**No Network Activity:** If this discovery was part of data exfiltration or C2 communication, those network connections aren't present in this timeframe.

**System Information Retrieved:** We don't see what geographic information was actually discovered or how it might be used by the attacker.

## Assessment

This dataset provides excellent coverage of the process execution aspects of system information discovery but limited insight into the data retrieved. The Security event logs with command-line auditing capture the essential evidence needed for detection engineering, showing the complete process chain and registry query attempt. The Sysmon process creation events add valuable context with parent-child relationships and process metadata.

The process access events (Sysmon EID 10) provide additional behavioral context, showing PowerShell's interaction with spawned child processes. However, the lack of registry access monitoring and actual query results limits the dataset's utility for understanding the full scope of information gathered.

For detection engineering purposes, this dataset strongly supports command-line based detections and process chain analysis, but would benefit from registry monitoring to capture the complete attack narrative.

## Detection Opportunities Present in This Data

1. **Registry Query Command Detection** - Security EID 4688 command lines containing `reg query` with geographic or system information paths like `Control Panel\International\Geo`

2. **PowerShell Child Process Spawning** - Sysmon EID 1 showing powershell.exe spawning cmd.exe or reg.exe for system discovery activities

3. **System Discovery Tool Execution** - Process creation of whoami.exe, reg.exe, or other system information utilities from scripting engines

4. **Process Chain Analysis** - Correlation of PowerShell → cmd.exe → reg.exe execution sequence within short time windows

5. **Geographic Location Registry Access** - Command-line patterns targeting `HKEY_CURRENT_USER\Control Panel\International\Geo` or similar location-related registry paths

6. **High-Privilege Process Access** - Sysmon EID 10 events showing PowerShell accessing child processes with full permissions (0x1FFFFF)

7. **Reconnaissance Behavior Clustering** - Multiple system information discovery tools executed in sequence from the same parent PowerShell process
