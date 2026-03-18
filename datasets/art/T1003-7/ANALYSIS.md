# T1003-7: OS Credential Dumping — Send NTLM Hash with RPC Test Connection

## Technique Context

T1003.007 represents a specific sub-technique of OS Credential Dumping that involves forcing authentication to capture NTLM hashes. The technique leverages Windows utilities that can establish authenticated connections to remote services, causing the current user's NTLM hash to be sent across the network where it can be captured by an attacker. The detection community focuses on monitoring for tools like `rpcping`, `nltest`, or other utilities that can initiate NTLM authentication challenges, especially when used with suspicious parameters or targeting localhost/loopback addresses.

This technique is particularly valuable to attackers because it doesn't require direct access to credential stores like LSASS—instead, it tricks the system into voluntarily transmitting hashes during authentication attempts. Detection strategies typically focus on process execution patterns, command-line analysis, and network activity associated with authentication protocols.

## What This Dataset Contains

The dataset captures a PowerShell-based execution of the technique using the `rpcping` utility. The key events show:

**Process Chain**: The execution flows through Security 4688 events showing: `powershell.exe` → `powershell.exe` (with rpcping command) → `RpcPing.exe -s 127.0.0.1 -e 1234 -a privacy -u NTLM`

**Command Line Evidence**: Security event 4688 captures the full command line: `"C:\Windows\system32\RpcPing.exe" -s 127.0.0.1 -e 1234 -a privacy -u NTLM`, which explicitly shows the NTLM authentication parameter and localhost targeting.

**Sysmon Coverage**: Sysmon EID 1 captures the RpcPing process creation with the same command line details and includes the RuleName `technique_id=T1003,technique_name=Credential Dumping (Likely)`, indicating the sysmon-modular config specifically flags this activity.

**PowerShell Telemetry**: EID 4104 script block logging captures the PowerShell wrapper: `& {rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM 1>$Null}`, showing the technique was executed through PowerShell with output redirection.

**Process Failure**: The RpcPing.exe process exits with status `0x6BA` (1722 decimal), indicating RPC_S_SERVER_UNAVAILABLE, which is expected when targeting a non-existent RPC endpoint but still triggers NTLM authentication.

## What This Dataset Does Not Contain

The dataset lacks network capture data that would show the actual NTLM authentication traffic or hash transmission—we only see the process execution attempt. Since the target (localhost:1234) is not a valid RPC endpoint, the authentication likely fails quickly without generating extensive network telemetry. 

There are no Security events related to authentication failures (4625) or Kerberos events, suggesting the NTLM challenge-response either didn't complete or wasn't logged at the expected detail level. The Sysmon network connection events (EID 3) present in the dataset are from Windows Defender, not from the RpcPing execution, indicating that either the connection attempt was too brief to capture or the sysmon-modular config doesn't capture localhost connections.

## Assessment

This dataset provides excellent detection opportunities from a process execution perspective. The Security 4688 events with command-line logging and Sysmon EID 1 events both clearly capture the suspicious rpcping execution with NTLM parameters. The PowerShell script block logging adds another detection layer by showing the wrapper script.

However, the dataset's utility is somewhat limited for network-based detection since it doesn't contain the actual authentication traffic that would be the primary target for network monitoring solutions. The technique's effectiveness relies on capturing NTLM hashes in transit, but this execution attempt appears to have failed before generating meaningful network authentication traffic.

## Detection Opportunities Present in This Data

1. **RpcPing with NTLM Authentication**: Monitor Security EID 4688 and Sysmon EID 1 for rpcping.exe execution with command lines containing `-u NTLM` parameters, especially when combined with localhost or loopback addresses.

2. **PowerShell Script Block Analysis**: Detect EID 4104 events containing rpcping commands with NTLM authentication parameters, particularly when output is redirected to null (indicating attempt to hide results).

3. **Process Chain Anomalies**: Alert on PowerShell spawning rpcping.exe processes, as this is uncommon in legitimate administrative scenarios and suggests scripted credential dumping attempts.

4. **Localhost RPC Targeting**: Flag rpcping executions targeting localhost (127.0.0.1) or loopback addresses with authentication parameters, as legitimate RPC diagnostics typically target remote systems.

5. **Failed RPC Connections with Authentication**: Monitor for rpcping processes that exit with specific error codes (like 0x6BA) when combined with NTLM authentication parameters, as this pattern indicates attempted credential extraction rather than legitimate RPC testing.

6. **Sysmon Rule Correlation**: Leverage existing Sysmon rule classifications that flag RpcPing as potential credential dumping activity (as shown by the technique_id=T1003 rule name in the dataset).
