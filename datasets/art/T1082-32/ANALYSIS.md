# T1082-32: System Information Discovery — ESXi - Darkside system information discovery

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries collect information about the compromised system's configuration, architecture, and environment. This specific test emulates the Darkside ransomware group's ESXi discovery methodology, which targeted virtualization infrastructure for maximum impact. The technique typically involves running built-in utilities like `whoami`, `systeminfo`, or platform-specific commands to gather host details, user context, and system capabilities. Detection engineers focus on monitoring process execution patterns, command-line arguments, and the sequence of discovery commands that indicate systematic reconnaissance behavior.

## What This Dataset Contains

This dataset captures a PowerShell-based execution that attempts to perform system discovery through multiple mechanisms. The Security event log shows the core activity with EID 4688 process creation events documenting the execution chain:

- `whoami.exe` execution with command line `"C:\Windows\system32\whoami.exe"` (PID 43892)
- `cmd.exe` execution attempting to use plink.exe for SSH-based discovery: `"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" "atomic.local" -ssh -l "root" -pw "pass" -m "C:\AtomicRedTeam\atomics\T1082\src\esx_darkside_discovery.txt"`
- A nested `cmd.exe` process (PID 42236) with command line `C:\Windows\system32\cmd.exe /S /D /c" echo "" "` showing the echo portion of the pipe operation

The Sysmon events provide additional process creation details through EID 1 events, including the RuleName tagging that identifies `whoami.exe` as "technique_id=T1033,technique_name=System Owner/User Discovery" and the cmd.exe processes as "technique_id=T1059.003,technique_name=Windows Command Shell". Multiple PowerShell processes (PIDs 42460, 43512, 43144) show .NET runtime loading and Windows Defender integration through EID 7 image load events.

The PowerShell operational log contains only test framework boilerplate - Set-StrictMode calls and Set-ExecutionPolicy Bypass commands with no actual discovery script content captured.

## What This Dataset Does Not Contain

The dataset shows a failed execution - the primary discovery mechanism (plink.exe SSH connection to "atomic.local") did not succeed, as evidenced by the cmd.exe process exit status of 0xFF (255) indicating failure. There are no Sysmon ProcessCreate events for plink.exe itself, suggesting either the executable was not found or execution failed immediately. The referenced discovery script file `C:\AtomicRedTeam\atomics\T1082\src\esx_darkside_discovery.txt` contents are not visible in the telemetry. No network connection events (Sysmon EID 3) appear, confirming the SSH connection attempt failed. The dataset lacks the comprehensive system information gathering that would typically result from successful ESXi discovery commands like `esxcli`, `vim-cmd`, or VMware-specific enumeration.

## Assessment

This dataset provides moderate value for detection engineering focused on reconnaissance attempt patterns rather than successful system discovery. The Security and Sysmon logs effectively capture the process execution chain and command-line arguments that reveal the intent to perform Darkside-style ESXi discovery. The failed nature of the test actually makes it more representative of real-world scenarios where attackers encounter missing tools, network connectivity issues, or environmental constraints. The presence of both native Windows tools (whoami.exe) and attempted third-party tool usage (plink.exe) provides detection opportunities for both basic and advanced discovery techniques. However, the lack of successful discovery output limits its utility for understanding the information disclosure aspects of the technique.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Monitor for cmd.exe executions containing plink.exe with SSH parameters and script file references, particularly targeting VMware/ESXi-related paths
2. **Reconnaissance tool sequence detection** - Alert on whoami.exe execution followed by SSH client attempts within short time windows, indicating systematic discovery
3. **Failed SSH connection attempts** - Track processes spawning SSH clients (plink.exe, ssh.exe) that exit with non-zero status codes, suggesting blocked or failed reconnaissance
4. **PowerShell process privilege escalation** - Monitor Security EID 4703 token right adjustments for PowerShell processes gaining extensive privileges (SeBackupPrivilege, SeRestorePrivilege, etc.)
5. **Atomic Red Team artifact detection** - Flag command lines containing AtomicRedTeam paths or ExternalPayloads references for test environment identification
6. **Process access pattern detection** - Sysmon EID 10 shows PowerShell accessing spawned discovery processes, indicating programmatic control over reconnaissance tools
7. **ESXi-specific discovery file access** - Monitor file access to paths containing "esx", "darkside", or VMware-related discovery scripts
