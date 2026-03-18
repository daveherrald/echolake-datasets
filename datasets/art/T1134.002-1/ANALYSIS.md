# T1134.002-1: Create Process with Token — Access Token Manipulation

## Technique Context

T1134.002 (Create Process with Token) is a privilege escalation and defense evasion technique where attackers create new processes using tokens from other processes, often to inherit elevated privileges or assume different user contexts. This is commonly achieved through Windows APIs like `CreateProcessWithTokenW()` or `CreateProcessAsUser()`. Attackers typically target high-privilege processes like LSASS to steal tokens and then spawn new processes with those elevated privileges. The detection community focuses on monitoring process creation events with unusual parent-child relationships, processes created with tokens from different security contexts, and API calls related to token manipulation. This technique is particularly dangerous because it allows privilege escalation while potentially evading detection by appearing as legitimate process creation.

## What This Dataset Contains

This dataset captures a PowerShell-based token manipulation attempt that appears to have been blocked by Windows Defender. The primary evidence includes:

**Process Creation Chain**: Security event 4688 shows the creation of `powershell.exe` with a complex command line: `"powershell.exe" & {Set-ExecutionPolicy -Scope Process Bypass -Force\n$owners = @{}\ngwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}\nGet-Process | Select ProcessName,Id,@{l=\"Owner\";e={$owners[$_.id.tostring()]}}\n& \"C:\AtomicRedTeam\atomics\T1134.002\src\GetToken.ps1\"; [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,\"cmd.exe\")}`

**PowerShell Script Execution**: Event 4104 shows the same command being executed, including the suspicious `GetToken.ps1` script and the call to `[MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")` - a clear attempt to create a process using LSASS's token.

**Process Access Events**: Sysmon event 10 shows PowerShell accessing other processes with `GrantedAccess: 0x1FFFFF` (full access), indicating token manipulation attempts.

**Token Privilege Adjustments**: Numerous Security events 4703 show "SeDebugPrivilege" being repeatedly disabled on WmiPrvSE.exe, and one event showing multiple high-privilege tokens being enabled on PowerShell including `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`.

**Windows Defender Activity**: Multiple MpCmdRun.exe processes were spawned, indicating real-time protection intervention.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful token manipulation execution. There are no Security events 4624/4648 showing new logon sessions created with different tokens, no evidence of cmd.exe being successfully spawned with LSASS privileges, and no Sysmon events showing the actual token creation process. This absence suggests Windows Defender successfully blocked the technique before completion. The dataset also lacks ETW events that would show detailed API calls to token manipulation functions, and there are no events indicating successful privilege escalation or execution with elevated tokens.

## Assessment

This dataset provides excellent telemetry for detecting attempted token manipulation but limited visibility into successful execution due to Windows Defender's intervention. The Security audit logs with command-line logging capture the complete attack intent, while Sysmon events provide process relationship context and access patterns. The PowerShell script block logging is particularly valuable as it records the exact malicious commands. However, the dataset's primary limitation is that it represents a blocked attack, so detection engineers studying this data should be aware they're seeing attempt telemetry rather than success indicators. The combination of Security 4688, Sysmon 1/10, and PowerShell 4104 events provides comprehensive coverage for building detections around this technique.

## Detection Opportunities Present in This Data

1. **Command Line Analysis**: Monitor Security 4688 and Sysmon 1 for PowerShell executions containing "GetToken", "CreateProcessFromParent", or "Get-Process lsass" patterns

2. **PowerShell Script Block Detection**: Alert on PowerShell 4104 events containing token manipulation functions like "CreateProcessWithToken" or references to LSASS process ID extraction

3. **Process Access Monitoring**: Detect Sysmon 10 events where PowerShell or other unexpected processes access multiple processes with full privileges (0x1FFFFF)

4. **Token Privilege Escalation**: Monitor Security 4703 events for privilege adjustments, especially when SeAssignPrimaryTokenPrivilege or SeIncreaseQuotaPrivilege are enabled on non-service processes

5. **Suspicious Parent-Child Relationships**: Correlate Security 4688 events to identify processes spawned by PowerShell with different token elevation types or user contexts

6. **LSASS Interaction Patterns**: Alert on any non-system process querying LSASS process information followed by process creation attempts

7. **Atomic Red Team Indicator**: Monitor for file paths containing "AtomicRedTeam" or "GetToken.ps1" in command lines or PowerShell scripts
