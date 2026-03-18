# T1021.001-2: Remote Desktop Protocol — Changing RDP Port to Non Standard Port via Powershell

## Technique Context

T1021.001 focuses on Remote Desktop Protocol (RDP) as a lateral movement technique, where attackers leverage legitimate RDP functionality to move between systems in a network. While RDP is commonly used for legitimate remote administration, attackers often abuse it after obtaining valid credentials through other means. A key evasion tactic is changing RDP's default port (3389) to a non-standard port to avoid detection by security tools that monitor standard RDP traffic. This technique is particularly effective because it maintains the legitimate appearance of RDP while potentially bypassing network monitoring focused on default ports. The detection community typically focuses on monitoring registry modifications to RDP configuration keys, unusual PowerShell usage for system configuration changes, and firewall rule creation that opens non-standard ports.

## What This Dataset Contains

This dataset captures a PowerShell-based RDP port modification technique executed as NT AUTHORITY\SYSTEM. The core malicious activity is visible in Security event 4688, which shows the execution of: `"powershell.exe" & {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "PortNumber" -Value 4489; New-NetFirewallRule -DisplayName 'RDPPORTLatest-TCP-In' -Profile 'Public' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 4489}`. 

The PowerShell channel provides detailed command invocation logging in events 4103, showing the specific cmdlet executions: `Set-ItemProperty` targeting the RDP registry path and `New-NetFirewallRule` creating firewall access for port 4489. Script block logging in event 4104 captures the full command structure.

Sysmon captures the process creation chain showing the parent PowerShell process (PID 2772) spawning a child PowerShell process (PID 1440) to execute the registry and firewall modifications. Registry modification evidence appears in Sysmon event 13, documenting the firewall rule creation: `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{918df86b-2508-4eb9-aa33-45b63c9ebe82}` with value `v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=4489|Name=RDPPORTLatest-TCP-In|`.

## What This Dataset Does Not Contain

The dataset lacks the direct registry modification to the RDP port configuration itself - there's no Sysmon event 13 showing the actual `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` registry value being changed to 4489. This is likely because the Sysmon configuration doesn't monitor that specific registry path, focusing instead on more commonly abused locations. Additionally, there are no network connection events showing actual RDP traffic on the new port, as this technique only configures the capability rather than demonstrating usage. The dataset also doesn't contain evidence of RDP service restart or configuration reload, which would typically be required for port changes to take effect.

## Assessment

This dataset provides excellent coverage of PowerShell-based RDP port modification techniques. The combination of Security event 4688 with full command-line logging, PowerShell operational events 4103/4104 with detailed cmdlet parameters, and Sysmon registry monitoring creates a comprehensive detection foundation. The firewall rule creation captured in Sysmon event 13 is particularly valuable, as it provides registry-level evidence of the technique's impact. The process lineage captured through Sysmon event 1 enables detection of suspicious PowerShell spawning patterns. While missing the direct RDP port registry modification, the dataset's strength lies in its detailed PowerShell execution telemetry and firewall configuration changes, which are often more reliable detection points than registry monitoring alone.

## Detection Opportunities Present in This Data

1. **PowerShell RDP Registry Modification** - Security 4688 and PowerShell 4103 events showing `Set-ItemProperty` targeting `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` with `PortNumber` parameter changes

2. **Firewall Rule Creation for Non-Standard Ports** - Sysmon 13 registry writes to `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` containing TCP port numbers outside standard ranges (not 3389, 80, 443, etc.)

3. **PowerShell Script Block Analysis** - PowerShell 4104 events containing both `Set-ItemProperty` and `New-NetFirewallRule` cmdlets in the same script block, indicating combined RDP reconfiguration and firewall opening

4. **Suspicious PowerShell Command Line Patterns** - Security 4688 showing PowerShell executions with embedded commands targeting Terminal Server registry paths and firewall rule creation for specific TCP ports

5. **Process Chain Analysis** - Sysmon 1 showing PowerShell processes spawning child PowerShell processes with RDP-related command lines, indicating potential scripted RDP manipulation

6. **Firewall Rule Naming Patterns** - Registry values in firewall rules containing RDP-related display names (`RDPPORTLatest-TCP-In`) combined with non-standard port numbers

7. **PowerShell Cmdlet Parameter Correlation** - PowerShell 4103 events showing `New-NetFirewallRule` with `LocalPort` parameters matching `Set-ItemProperty` `Value` parameters in temporal proximity
