# T1135-11: Network Share Discovery — Enumerate All Network Shares with SharpShares

## Technique Context

Network Share Discovery (T1135) involves adversaries enumerating network shares on local and remote systems to identify accessible file shares that may contain sensitive data or provide lateral movement opportunities. This technique is fundamental to the discovery phase of attacks, as shared resources often contain valuable intelligence or serve as staging areas for further compromise.

SharpShares is a C# implementation of share enumeration that uses LDAP queries to discover network shares across Active Directory environments. Unlike traditional net.exe commands that target individual systems, SharpShares can efficiently enumerate shares across multiple domain-joined systems, making it particularly valuable for reconnaissance in enterprise environments. The detection community focuses on monitoring for unusual share enumeration patterns, especially when targeting multiple systems or originating from unexpected sources.

## What This Dataset Contains

This dataset captures a PowerShell-based execution of SharpShares with comprehensive telemetry across multiple data sources:

**Process Chain Evidence:**
- Security 4688 shows the complete process chain: `powershell.exe` → `powershell.exe` with command `"powershell.exe" & {cmd /c 'C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpShares.exe' /ldap:all | out-file -filepath \""$env:temp\T1135SharpSharesOutput.txt\""}`
- Sysmon EID 1 captures the cmd.exe spawning with command line: `"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpShares.exe /ldap:all`
- Notably, SharpShares.exe itself does not appear in process creation events, suggesting the sysmon-modular config filters don't match this executable pattern

**PowerShell Script Block Logging:**
- EID 4104 captures the actual command execution: `& {cmd /c 'C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpShares.exe' /ldap:all | out-file -filepath "$env:temp\T1135SharpSharesOutput.txt"}`
- Shows the `/ldap:all` parameter indicating LDAP-based enumeration across the domain
- Documents output redirection to `T1135SharpSharesOutput.txt` in the temp directory

**File System Activity:**
- Sysmon EID 11 shows file creation of `C:\Windows\Temp\T1135SharpSharesOutput.txt` by the PowerShell process
- This indicates successful execution and output capture

**Process Access Behavior:**
- Sysmon EID 10 shows PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- Process access events indicate PowerShell's job control and process management during execution

## What This Dataset Does Not Contain

The dataset lacks several key elements that would provide a complete picture of the technique:

**Missing Network Activity:**
- No Sysmon EID 3 (Network Connection) events showing LDAP queries to domain controllers
- No DNS resolution events (EID 22) for target systems discovery
- Missing authentication events (Security 4624/4625) that would typically accompany domain enumeration

**Limited Tool Telemetry:**
- SharpShares.exe process creation is not captured, likely due to sysmon-modular include-mode filtering
- No image load events for SharpShares.exe showing its dependencies or injection techniques
- Missing detailed command-line arguments parsing beyond the basic `/ldap:all` parameter

**Incomplete Output Analysis:**
- The created output file content is not accessible, preventing analysis of discovered shares
- No follow-on activity showing how enumerated shares might be accessed or exploited

## Assessment

This dataset provides good coverage for detecting PowerShell-based network share enumeration tools, particularly through command-line analysis and script block logging. The Security 4688 events with command-line logging effectively capture the tool invocation, while PowerShell script block logging (EID 4104) provides the complete execution context including parameters and output redirection.

The process chain visibility is excellent for behavioral detection, showing the characteristic pattern of PowerShell spawning cmd.exe to execute external enumeration tools. However, the lack of network telemetry significantly limits the dataset's utility for understanding the actual enumeration behavior and network-based detection opportunities.

The file creation event for the output file provides a concrete artifact that could be valuable for forensic analysis, though the file contents themselves aren't available in the telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection** - Monitor Security 4688 events for command lines containing "SharpShares.exe" or similar share enumeration tools with LDAP parameters

2. **Script Block Analysis** - Alert on PowerShell EID 4104 events containing network enumeration tool execution patterns, particularly those redirecting output to files

3. **Suspicious Process Chains** - Detect PowerShell spawning cmd.exe to execute external binaries from non-standard locations like AtomicRedTeam directories

4. **File Artifact Creation** - Monitor Sysmon EID 11 for creation of files with naming patterns suggesting enumeration output (e.g., files containing "SharesOutput", "NetEnum", etc.)

5. **Process Access Behavior** - Correlate Sysmon EID 10 events showing PowerShell accessing multiple child processes as potential indicators of automated tool execution

6. **External Tool Staging** - Alert on execution of binaries from ExternalPayloads or similar staging directories that may indicate red team tool usage

7. **Parameter-Based Detection** - Monitor for command lines containing "/ldap:all" or similar domain-wide enumeration parameters that indicate broad reconnaissance activity
