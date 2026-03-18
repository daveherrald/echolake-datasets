# T1040-5: Network Sniffing — Windows Internal Packet Capture

## Technique Context

T1040 Network Sniffing involves capturing network packets to intercept sensitive data in transit, including credentials, configuration information, or other valuable intelligence. Attackers commonly use built-in Windows utilities like netsh trace, Wireshark, or custom packet capture tools to perform network monitoring. The detection community focuses on process creation events for network capture utilities, unusual network driver installations, file creation patterns for packet capture files (.pcap, .etl), and registry modifications related to network interfaces or packet capture services.

## What This Dataset Contains

This dataset captures the execution of `netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10` through PowerShell, demonstrating Windows' built-in packet capture capability. The complete process chain is visible:

- PowerShell (PID 6240) spawns cmd.exe with command `"cmd.exe" /c netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10` (Security 4688)
- cmd.exe (PID 880) launches netsh.exe with the expanded command `netsh trace start capture=yes tracefile=C:\Windows\TEMP\trace.etl maxsize=10` (Security 4688, Sysmon 1)
- Sysmon captures the netsh.exe process creation (EID 1) with the full command line showing packet capture parameters
- File creation of `C:\Windows\Temp\trace.etl` (Sysmon 11) documenting the ETL trace file creation
- Registry modifications showing NdisCap service configuration (Sysmon 13) setting NDIS version parameters for network packet capture driver
- Process access events (Sysmon 10) showing PowerShell accessing both whoami.exe and cmd.exe processes

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks) with no technique-specific content.

## What This Dataset Does Not Contain

The dataset lacks network connection telemetry showing actual packet capture activity — Sysmon network events would show if the technique successfully initiated network monitoring. There are no events indicating packet data being written to the ETL file beyond the initial file creation. The dataset also doesn't contain Windows Defender blocking attempts, suggesting the technique executed successfully. Missing are any application-layer events from the ETW (Event Tracing for Windows) subsystem that would show trace session creation and packet capture statistics.

## Assessment

This dataset provides excellent telemetry for detecting Windows internal packet capture through netsh trace. The combination of Security 4688 command-line auditing, Sysmon ProcessCreate (EID 1), file creation (EID 11), and registry modifications (EID 13) creates a comprehensive detection profile. The command-line visibility is particularly strong, capturing both the initial cmd.exe invocation and the final netsh.exe execution with full parameters. The registry modifications to NdisCap service values provide additional technical indicators specific to Windows packet capture functionality.

## Detection Opportunities Present in This Data

1. **Netsh Trace Command Execution** — Security 4688 and Sysmon EID 1 events showing netsh.exe with "trace start capture=yes" parameters in command line
2. **ETL File Creation Pattern** — Sysmon EID 11 showing creation of .etl files in temporary directories, particularly with "trace" naming conventions
3. **NdisCap Registry Modifications** — Sysmon EID 13 events showing registry writes to `HKLM\System\CurrentControlSet\Services\NdisCap\` keys indicating packet capture driver configuration
4. **Process Chain Analysis** — PowerShell spawning cmd.exe spawning netsh.exe, indicating indirect execution of network capture utilities
5. **Command Line Obfuscation Detection** — Compare initial cmd.exe command with environment variable `%temp%` against final netsh.exe execution with expanded path
6. **Network Capture File Monitoring** — File creation events for common packet capture extensions (.etl, .pcap, .cap) in temporary directories
7. **Privilege Escalation Context** — Process creation events showing SYSTEM-level execution of network capture utilities, indicating potential administrative access
