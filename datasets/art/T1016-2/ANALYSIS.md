# T1016-2: System Network Configuration Discovery — List Windows Firewall Rules

## Technique Context

T1016 System Network Configuration Discovery is a fundamental reconnaissance technique where adversaries gather information about network configurations to understand the target environment. The specific test T1016-2 focuses on enumerating Windows Firewall rules using the `netsh advfirewall firewall show rule name=all` command. This technique is commonly used by attackers during the discovery phase to understand network security controls, identify potential bypass opportunities, and map out allowed/blocked network communications. Detection engineers typically focus on monitoring command-line executions of network configuration tools like netsh, especially when used with firewall-related parameters.

## What This Dataset Contains

This dataset captures a PowerShell-executed firewall enumeration sequence with comprehensive telemetry across multiple channels:

**Security Channel Events:**
- Process creation (EID 4688) for the complete process chain: powershell.exe → cmd.exe → netsh.exe
- Command lines captured: `"cmd.exe" /c netsh advfirewall firewall show rule name=all` and `netsh advfirewall firewall show rule name=all`
- Process termination events (EID 4689) showing successful completion (exit status 0x0)
- Token privilege adjustments (EID 4703) for PowerShell process

**Sysmon Channel Events:**
- Process creation events (EID 1) for whoami.exe, cmd.exe, and netsh.exe with full command lines and parent process relationships
- Process access events (EID 10) showing PowerShell accessing both whoami.exe and cmd.exe processes
- Image load events (EID 7) for PowerShell .NET runtime initialization
- Named pipe creation (EID 17) for PowerShell host communication

**PowerShell Channel Events:**
- Script block logging (EID 4104) and command invocation logging (EID 4103) showing Set-ExecutionPolicy bypass commands
- The actual firewall enumeration commands are not directly visible in PowerShell logs, indicating execution through cmd.exe subprocess

The dataset shows execution under NT AUTHORITY\SYSTEM context, launched from a PowerShell process (PID 7188) that spawned both whoami.exe for user discovery and the cmd.exe/netsh.exe chain for firewall enumeration.

## What This Dataset Does Not Contain

The dataset does not capture the actual output of the netsh command showing firewall rules, as this would be written to stdout rather than Windows event logs. Network connections or DNS queries are absent since this is a local configuration query. The PowerShell script block logs don't contain the actual discovery commands, only test framework boilerplate, because the technique uses PowerShell to invoke cmd.exe rather than executing netsh directly through PowerShell cmdlets. Registry modifications or file system artifacts related to the firewall enumeration are not present. The technique completed successfully (exit code 0x0), so there are no error conditions or Defender blocking events in this dataset.

## Assessment

This dataset provides excellent detection coverage for the T1016-2 technique through multiple complementary data sources. The Security channel offers the most reliable detection opportunities with process creation events containing full command lines, while Sysmon adds valuable process relationships and access patterns. The combination of process creation, command-line logging, and parent-child process relationships creates multiple detection pivot points. However, the dataset would be stronger with the actual netsh output capture or additional context about what firewall rules were enumerated. The PowerShell channel provides limited value for this specific technique since the actual enumeration occurs in subprocesses.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Monitor Security EID 4688 for processes executing `netsh` with `advfirewall` and `show rule` parameters
2. **Process chain analysis** - Detect Security EID 4688 events showing powershell.exe spawning cmd.exe with netsh firewall enumeration commands
3. **PowerShell subprocess enumeration** - Monitor Sysmon EID 1 for cmd.exe processes with netsh firewall parameters launched by PowerShell parents
4. **Network configuration tool abuse** - Alert on netsh.exe execution with firewall-related arguments, particularly when spawned from scripting engines
5. **System discovery sequence correlation** - Correlate whoami.exe execution (user discovery) followed by netsh firewall enumeration within the same PowerShell session
6. **Privileged enumeration detection** - Monitor for netsh firewall commands executed in SYSTEM context, which may indicate automated reconnaissance
7. **Process access pattern monitoring** - Use Sysmon EID 10 to detect PowerShell processes accessing multiple discovery-related child processes (whoami, cmd/netsh)
