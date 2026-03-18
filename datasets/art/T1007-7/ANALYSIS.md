# T1007-7: System Service Discovery — System Service Discovery - Services Registry Enumeration

## Technique Context

System Service Discovery (T1007) is a Discovery technique where adversaries enumerate services to understand what's running on a system, helping them identify potential attack vectors, understand the system's security posture, and locate services that might be vulnerable or useful for persistence. The technique is fundamental to post-compromise reconnaissance and environment mapping.

This specific test implements registry enumeration of services by directly querying `HKLM:\SYSTEM\CurrentControlSet\Services` using PowerShell's registry provider. Unlike using `sc query` or WMI, this approach bypasses service control manager APIs and directly reads the service configuration data from the registry. The detection community focuses on PowerShell registry access patterns, particularly bulk enumeration of the Services registry key, as well as process creation patterns that indicate service discovery activities.

## What This Dataset Contains

This dataset captures a PowerShell-based service enumeration technique that reads directly from the Windows registry. The core activity is documented in Security event 4688 showing process creation for `powershell.exe` with the command line:
```
"powershell.exe" & {Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue [PSCustomObject]@{ Name = $_.PSChildName DisplayName = $p.DisplayName ImagePath = $p.ImagePath StartType = $p.Start } }}
```

Sysmon provides detailed process creation telemetry in event 1, showing the new PowerShell process (PID 7004) with the full command line. The technique also triggers process access events (Sysmon event 10) showing inter-process communication between PowerShell processes, and extensive image loading events (Sysmon event 7) as PowerShell loads .NET framework components and Windows Defender integration DLLs.

The PowerShell operational log contains extensive evidence of the registry enumeration, with hundreds of 4103 CommandInvocation events showing individual `Get-ItemProperty` calls for each service registry key (`.NET CLR Data`, `1394ohci`, `AarSvc`, etc.), demonstrating the systematic enumeration of all services. Event 4104 ScriptBlock events capture the actual PowerShell script content, including the registry path targeting and object construction logic.

## What This Dataset Does Not Contain

The dataset does not contain actual service enumeration output data - we only see the commands being executed, not their results. There are no network connections or file writes containing the enumerated service information, suggesting the data was only processed in memory or displayed to console.

The technique doesn't trigger any Windows Defender blocks or security alerts despite the extensive registry access, indicating this type of registry enumeration is considered normal administrative activity. There's no evidence of privilege escalation attempts or suspicious access to sensitive service configurations.

Missing are alternative service discovery methods like `sc.exe` queries, WMI service enumeration, or net commands that might be used in combination with registry enumeration for comprehensive service mapping.

## Assessment

This dataset provides excellent visibility into PowerShell-based registry enumeration techniques targeting Windows services. The Security event logs with command-line auditing capture the complete attack command, while Sysmon process creation events provide additional context and parent-child relationships. The PowerShell operational logs are particularly valuable, showing the detailed execution of individual registry queries across hundreds of service entries.

The data sources are well-suited for detecting this technique because they capture both the high-level command execution (Security 4688) and the granular registry access patterns (PowerShell 4103/4104). The extensive PowerShell logging provides forensic-quality evidence of what registry keys were accessed and in what sequence.

The dataset would be stronger with network telemetry to detect if enumerated service data is being exfiltrated, and with additional context about what legitimate administrative tools might generate similar registry access patterns for baseline comparison.

## Detection Opportunities Present in This Data

1. **PowerShell Registry Service Enumeration** - Detect PowerShell processes executing `Get-ChildItem` against `HKLM:\SYSTEM\CurrentControlSet\Services` with bulk property retrieval operations

2. **Service Registry Bulk Access Pattern** - Monitor for rapid sequential access to multiple service registry keys using `Get-ItemProperty` cmdlets within short time windows

3. **PowerShell Command Line Indicators** - Alert on process creation events containing `HKLM:\SYSTEM\CurrentControlSet\Services` combined with PowerShell registry cmdlets

4. **PowerShell ScriptBlock Analysis** - Detect ScriptBlock logging events (4104) containing service registry paths and systematic enumeration logic

5. **Registry Provider Service Discovery** - Monitor PowerShell operational logs for CommandInvocation events (4103) showing systematic `Get-ItemProperty` calls across service registry keys

6. **Process Relationship Analysis** - Correlate PowerShell parent-child process relationships with service discovery activities using Sysmon process creation events

7. **Bulk Registry Service Queries** - Detect processes making registry queries to multiple service keys within configurable time thresholds, indicating systematic enumeration rather than targeted service lookups
