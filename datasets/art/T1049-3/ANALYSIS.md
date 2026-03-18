# T1049-3: System Network Connections Discovery — System Network Connections Discovery via PowerShell (Process Mapping)

## Technique Context

T1049 System Network Connections Discovery is a foundational reconnaissance technique where adversaries enumerate active network connections to understand communication patterns, identify remote systems, and map network topology. This specific test demonstrates PowerShell-based network connection discovery with process mapping — using `Get-NetTCPConnection` combined with `Get-Process` to correlate network connections with their owning processes. This approach is particularly valuable to attackers because it reveals not just what connections exist, but which processes are responsible for them, enabling targeted process manipulation or lateral movement planning. Detection engineers focus on PowerShell execution patterns, specific cmdlet usage, and the combination of network enumeration with process discovery activities.

## What This Dataset Contains

The dataset captures a complete PowerShell-based network connection discovery execution. In Security events, we see the full command line in EID 4688 for process 18712: `"powershell.exe" & {Get-NetTCPConnection | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue [pscustomobject]@{ Local = \"$($_.LocalAddress):$($_.LocalPort)\" Remote = \"$($_.RemoteAddress):$($_.RemotePort)\" State = $_.State PID = $_.OwningProcess Process = if ($p) { $p.ProcessName } else { $null } } } | Sort-Object State,Process | Format-Table -AutoSize}`. 

The PowerShell logs contain extensive evidence of the technique execution. EID 4104 script blocks show the complete technique code: `Get-NetTCPConnection | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue [pscustomobject]@{ Local = "$($_.LocalAddress):$($_.LocalPort)" Remote = "$($_.RemoteAddress):$($_.RemotePort)" State = $_.State PID = $_.OwningProcess Process = if ($p) { $p.ProcessName } else { $null } } } | Sort-Object State,Process | Format-Table -AutoSize`. Multiple EID 4103 CommandInvocation events demonstrate the iterative process discovery, with `Get-Process` calls for PIDs including 4792, 740, 3240, 780, 2316, 1868, 632, 4, 5404, 6356, 524, 3972, 3576, 3456, 3588, 4068, and many calls to PID 0.

Sysmon events provide process lineage through EID 1 events showing the PowerShell process creation (PID 18712) with the full command line, and EID 10 process access events demonstrating the parent PowerShell process (PID 18784) accessing the child process. EID 7 events capture the loading of .NET assemblies including System.Management.Automation.ni.dll, confirming PowerShell execution context.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the network connection enumeration — we see the PowerShell commands executing but not the discovered connection data that would be returned. There are no network connection establishment events (Sysmon EID 3) since this technique only enumerates existing connections rather than creating new ones. The dataset doesn't capture any file-based artifacts of the discovery results, as the technique outputs to console rather than persisting findings. Additionally, we don't see any suspicious network connections that might indicate actual malicious activity — the technique ran in a relatively clean lab environment.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based network connection discovery with process mapping. The combination of Security 4688 process creation with full command lines, extensive PowerShell 4103/4104 logging showing cmdlet invocations and script blocks, and Sysmon process creation events creates multiple detection layers. The PowerShell logs are particularly valuable, capturing both the high-level technique implementation and the granular cmdlet-by-cmdlet execution showing specific PIDs being queried. The process lineage from Sysmon adds context for understanding execution chains. This multi-layered telemetry enables robust detection rule development targeting both the specific PowerShell cmdlet patterns and broader behavioral indicators.

## Detection Opportunities Present in This Data

1. **PowerShell Network Discovery Cmdlet Sequence** - Detect the combination of `Get-NetTCPConnection` and `Get-Process` cmdlets within the same PowerShell session, particularly when used in ForEach-Object loops

2. **Command Line Pattern Matching** - Hunt for Security 4688 events containing PowerShell command lines with `Get-NetTCPConnection` combined with process enumeration patterns

3. **PowerShell Script Block Analysis** - Monitor PowerShell 4104 events for script blocks containing network connection enumeration logic combined with process discovery

4. **Iterative Process Access Patterns** - Correlate multiple `Get-Process` calls with specific PID parameters (visible in 4103 CommandInvocation events) as indicators of systematic process discovery

5. **PowerShell Module Loading Correlation** - Link Sysmon EID 7 System.Management.Automation.ni.dll loads with subsequent network enumeration cmdlet execution

6. **Parent-Child PowerShell Process Relationships** - Detect PowerShell processes spawning additional PowerShell instances for network discovery operations using Sysmon EID 1 process creation events

7. **Console Output Formatting Indicators** - Monitor for PowerShell usage of `Format-Table -AutoSize` in conjunction with network discovery cmdlets as evidence of human-readable output generation

8. **Cross-Reference Network and Process Discovery** - Build behavioral rules detecting the temporal correlation between network connection enumeration and systematic process querying within short time windows
