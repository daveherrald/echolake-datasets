# T1021.002-1: SMB/Windows Admin Shares — Map admin share

## Technique Context

T1021.002 (SMB/Windows Admin Shares) is a lateral movement technique where attackers map or connect to administrative shares (like C$, ADMIN$, IPC$) on remote systems to move laterally through a network. This technique leverages Windows' built-in file sharing capabilities and administrative shares that are automatically created on Windows systems. Attackers typically use credentials they've obtained through credential dumping, brute forcing, or other means to authenticate to these shares and then copy files, execute commands, or establish persistence on remote systems.

The detection community focuses on monitoring for suspicious SMB connections, especially those using administrative shares, net use commands with credentials, authentication failures followed by successes, and unusual patterns of lateral movement across multiple systems. Key indicators include command-line usage of net use with admin shares, SMB authentication events, and process creation patterns associated with remote execution.

## What This Dataset Contains

This dataset captures an attempted SMB admin share mapping using the `net use` command. The key telemetry shows:

**Process Chain**: PowerShell → cmd.exe → cmd.exe → net.exe with the command line `"net use \\Target\C$ P@ssw0rd1 /u:DOMAIN\Administrator"`

**Security Events**: Security 4688 events show the complete process creation chain, with the final net.exe command containing the full SMB mapping attempt including hardcoded credentials and target host "Target"

**DNS Resolution Attempts**: Sysmon EID 22 events show DNS queries for "Target" and "target" with QueryStatus 9003 (DNS name does not exist), indicating the target host could not be resolved

**Process Access**: Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF)

**Exit Codes**: All processes exit with status 0x2, indicating the net use command failed (likely due to the non-existent target host)

## What This Dataset Does Not Contain

This dataset lacks several key elements that would be present in a successful SMB lateral movement attempt:

- **No network connection events**: Since the DNS resolution fails, there are no Sysmon EID 3 (NetworkConnect) events showing actual SMB connections
- **No authentication events**: Missing Security 4624/4625 logon events that would show authentication attempts to the remote system
- **No file operations**: No Sysmon EID 11 events showing files being copied to/from the remote share
- **No successful share mapping**: The technique fails at the DNS resolution stage, so we don't see the telemetry of a successful admin share connection
- **Limited PowerShell content**: The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual technique implementation

## Assessment

This dataset provides good visibility into the process execution patterns of SMB admin share mapping attempts but represents a failed execution due to DNS resolution failure. The Security channel with command-line auditing captures the complete attack chain including credentials in plaintext, which is valuable for detection engineering. However, the lack of actual network activity limits its utility for testing detections focused on SMB protocol behavior or successful lateral movement indicators.

The data is most useful for building detections around suspicious command-line patterns and process relationships, but less valuable for network-based detection rules or post-compromise activity monitoring.

## Detection Opportunities Present in This Data

1. **Net use with admin shares and credentials**: Security 4688 events showing `net use \\hostname\C$` patterns with embedded credentials in command lines

2. **Suspicious process chain patterns**: PowerShell spawning cmd.exe which spawns net.exe, indicating potential automation or scripting of lateral movement

3. **Credential exposure in command lines**: Plaintext passwords visible in Security 4688 Process Command Line fields for net.exe execution

4. **DNS queries for internal hostnames**: Sysmon EID 22 showing DNS resolution attempts for internal target systems, especially with failure status codes

5. **Failed lateral movement attempts**: Correlation of DNS resolution failures (QueryStatus 9003) with subsequent net use commands indicating reconnaissance or failed attack attempts

6. **Process access patterns**: Sysmon EID 10 showing PowerShell accessing cmd.exe with full rights, potentially indicating process injection or manipulation techniques

7. **Multiple cmd.exe spawning**: Nested cmd.exe process creation which is often associated with batch file execution or command obfuscation techniques
