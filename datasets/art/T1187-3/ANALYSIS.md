# T1187-3: Forced Authentication — Trigger an authenticated RPC call to a target server with no Sign flag set

## Technique Context

T1187 Forced Authentication is a credential access technique where attackers force a system to authenticate to a remote location under their control, potentially capturing authentication material like NTLM hashes or Kerberos tickets. This specific test (T1187-3) uses the legitimate Windows utility `rpcping.exe` to trigger an authenticated RPC call with NTLM authentication to a target endpoint (127.0.0.1:9997) without the Sign flag, making the authentication attempt more vulnerable to interception.

The detection community focuses on unusual uses of RPC-related tools, unexpected network authentication attempts, and processes that generate authentication traffic to suspicious or non-standard endpoints. `rpcping.exe` is particularly interesting because it's a legitimate Microsoft utility that can force authentication attempts, making it attractive for adversaries conducting credential theft or lateral movement reconnaissance.

## What This Dataset Contains

The dataset captures the complete execution chain of this forced authentication technique:

**Process execution chain:** PowerShell launches `rpcping.exe` with the command `"C:\Windows\system32\RpcPing.exe" -s 127.0.0.1 -e 9997 /a connect /u NTLM`. The Security log shows the full process creation in EID 4688 events, while Sysmon EID 1 captures the RpcPing.exe launch with process GUID {9dc7570a-7d19-69b4-035a-000000001000}.

**PowerShell scriptblock logging:** The PowerShell channel captures the technique's execution in EID 4104: `{rpcping -s 127.0.0.1 -e 9997 /a connect /u NTLM 1>$Null}`, showing the exact command structure and output redirection.

**Process termination:** The RpcPing.exe process exits with status 0x6BA (error code 1722 - "The RPC server is unavailable"), indicating the connection attempt failed as expected since no RPC server was listening on port 9997.

**System-level artifacts:** Multiple Sysmon EID 10 events show PowerShell accessing child processes with full access rights (0x1FFFFF), and EID 7 events capture .NET framework DLL loading in the PowerShell processes.

## What This Dataset Does Not Contain

**Network-level evidence:** While the technique attempts to generate network authentication, there are no Sysmon EID 3 (Network Connection) events showing the actual connection attempt to 127.0.0.1:9997. This could indicate the connection failed before establishment or that the sysmon-modular configuration filters out localhost connections.

**Authentication logs:** No EID 4624/4625 logon events or Kerberos/NTLM authentication events appear in the Security log, suggesting the authentication attempt was unsuccessful due to no service listening on the target port.

**DNS resolution:** No Sysmon EID 22 DNS query events are present since the target is a direct IP address (127.0.0.1).

**RPC-specific telemetry:** Windows doesn't provide detailed RPC client-side logging by default, so the actual RPC authentication negotiation details aren't captured in standard event logs.

## Assessment

This dataset provides excellent telemetry for detecting the process execution aspects of forced authentication attacks using rpcping.exe. The combination of Security 4688 events with command-line logging and Sysmon EID 1 events gives defenders clear visibility into the technique's execution. The PowerShell scriptblock logging (EID 4104) is particularly valuable as it captures the exact command syntax.

However, the dataset's utility for detecting the networking aspects of forced authentication is limited since the connection attempt failed. In a real attack scenario where authentication succeeds, you would expect to see additional network connection events and potentially authentication logs that aren't present here.

The process exit code (0x6BA) is actually diagnostic - it indicates the RPC server was unavailable, which could be used to detect failed forced authentication attempts alongside successful ones.

## Detection Opportunities Present in This Data

1. **Unusual rpcping.exe execution** - Monitor Sysmon EID 1 and Security EID 4688 for rpcping.exe launched with authentication parameters (`/u NTLM`, `/a connect`) targeting non-standard ports or IP addresses outside normal infrastructure ranges.

2. **PowerShell launching RPC utilities** - Detect PowerShell processes (Sysmon EID 1 ParentImage contains "powershell.exe") spawning rpcping.exe or other RPC-related utilities, especially with authentication flags.

3. **Forced authentication command patterns** - Alert on PowerShell scriptblock content (EID 4104) containing rpcping commands with authentication parameters, particularly when combined with output redirection to hide results.

4. **Process access patterns** - Monitor Sysmon EID 10 events where PowerShell accesses child RPC utility processes with high access rights (0x1FFFFF), which may indicate programmatic control of authentication tools.

5. **RPC tool exit codes** - Track Security EID 4689 process termination events for rpcping.exe with specific exit codes (0x6BA indicates RPC server unavailable, but other codes might indicate successful or different types of authentication attempts.

6. **Localhost targeting anomalies** - Flag rpcping.exe executions targeting localhost (127.0.0.1) with non-standard ports, as this pattern is unusual in legitimate administrative use but common in testing/attack scenarios.
