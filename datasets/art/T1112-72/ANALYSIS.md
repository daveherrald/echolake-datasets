# T1112-72: Modify Registry — Setting Shadow key in Registry for RDP Shadowing

## Technique Context

T1112 (Modify Registry) encompasses adversary techniques that modify Windows Registry keys and values to achieve persistence, defense evasion, or privilege escalation. The specific test T1112-72 focuses on enabling RDP shadowing functionality through registry modification. RDP shadowing allows an administrator to remotely view or take control of another user's desktop session without notification. While legitimate for administrative purposes, attackers abuse this capability for persistence and lateral movement.

This technique modifies the `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\shadow` registry value to enable shadowing permissions. The detection community monitors registry modifications to Terminal Services keys as they can indicate unauthorized remote access configuration. The combination of firewall rule changes and registry modifications for RDP services is particularly suspicious when executed programmatically.

## What This Dataset Contains

The dataset captures a PowerShell-based implementation that uses CIM/WMI to both enable Windows Firewall rules and modify the registry. The core technique manifests in these key events:

Security 4688 events show the process creation: `"powershell.exe" & {$s= New-CimSession -Computername localhost -SessionOption (New-CimSessionOption -Protocol Dcom) Get-CimInstance -Namespace ROOT\StandardCimv2 -ClassName MSFT_NetFirewallRule -Filter 'DisplayName="Remote Desktop - Shadow (TCP-In)"' -CimSession $s | Invoke-CimMethod -MethodName Enable Invoke-CimMethod -ClassName StdRegProv -MethodName SetDWORDValue -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName="Software\Policies\Microsoft\Windows NT\Terminal Services"; sValueName="shadow"; uValue=[uint32]2} -CimSession $s}"`

PowerShell 4103 events capture the detailed CIM method invocations: `CommandInvocation(Invoke-CimMethod): "Invoke-CimMethod" ParameterBinding(Invoke-CimMethod): name="ClassName"; value="StdRegProv" ParameterBinding(Invoke-CimMethod): name="MethodName"; value="SetDWORDValue"`

The critical registry modification appears in Sysmon 13: `Registry value set: TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\shadow Details: DWORD (0x00000002)` performed by `C:\Windows\system32\wbem\wmiprvse.exe`.

Additional Sysmon events capture firewall rule modifications: `TargetObject: HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\RemoteDesktop-Shadow-In-TCP Details: v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=%%SystemRoot%%\system32\RdpSa.exe`

## What This Dataset Does Not Contain

The dataset lacks direct registry modification events from the PowerShell process itself. The registry change occurs through WMI (wmiprvse.exe), which is the expected behavior for CIM-based registry operations but may complicate attribution in some detection rules that expect direct process-to-registry relationships.

The dataset doesn't contain the actual RDP shadowing attempts or connections that would follow this configuration change. It also lacks any cleanup or restoration of the original settings, making this a one-way configuration change.

There are no explicit privilege escalation events, though the PowerShell processes run as NT AUTHORITY\SYSTEM, indicating the technique requires administrative privileges to execute successfully.

## Assessment

This dataset provides excellent detection opportunities for registry-based persistence techniques. The combination of PowerShell script block logging (4104), command invocation logging (4103), and Sysmon registry monitoring (13) creates multiple detection layers. The specific registry path and value (`shadow = 2`) are highly distinctive indicators.

The use of CIM/WMI for registry modification creates an additional detection dimension through the wmiprvse.exe process performing the actual registry write. This indirect approach may bypass some basic registry monitoring that only tracks direct process-to-registry operations.

The PowerShell telemetry is comprehensive, capturing both the high-level script blocks and granular parameter bindings for the CIM operations. The full command line in Security 4688 events provides immediate context for the technique's intent.

## Detection Opportunities Present in This Data

1. **Registry modification to Terminal Services shadow key** - Monitor Sysmon EID 13 for `TargetObject` containing `\Terminal Services\shadow` with `Details` value of `DWORD (0x00000002)`

2. **PowerShell CIM registry operations** - Detect PowerShell 4103 events with `ClassName` of `StdRegProv` and `MethodName` of `SetDWORDValue` targeting Terminal Services registry paths

3. **Firewall rule modifications for RDP shadowing** - Alert on registry changes to `FirewallPolicy\FirewallRules\RemoteDesktop-Shadow-In-TCP` with `Action=Allow`

4. **Combined RDP configuration changes** - Correlate firewall rule enabling with Terminal Services registry modifications within the same process tree or time window

5. **WMI-mediated registry writes** - Monitor wmiprvse.exe (Sysmon EID 13) writing to Terminal Services policy keys, especially when initiated by PowerShell processes

6. **PowerShell script block analysis** - Search PowerShell 4104 events for script blocks containing `StdRegProv`, `SetDWORDValue`, and `Terminal Services` keywords in combination

7. **Process tree analysis** - Detect PowerShell parent processes spawning child PowerShell with CIM-related command lines containing Terminal Services references
