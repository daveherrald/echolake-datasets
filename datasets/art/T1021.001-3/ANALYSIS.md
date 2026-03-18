# T1021.001-3: Remote Desktop Protocol — Changing RDP Port to Non Standard Port via Command_Prompt

## Technique Context

T1021.001 Remote Desktop Protocol is a lateral movement technique where attackers use RDP to move between systems in a network. A common defensive evasion variant involves changing RDP from its default port 3389 to a non-standard port to avoid detection and network monitoring. This technique is frequently used by ransomware groups, APTs, and opportunistic attackers to maintain persistence while evading port-based security controls.

The detection community typically focuses on registry modifications to RDP configuration keys, firewall rule additions for non-standard ports, and the use of administrative utilities like `reg.exe` and `netsh.exe` to modify system configurations. This particular test simulates an attacker changing RDP to port 4489 and creating a corresponding firewall rule.

## What This Dataset Contains

This dataset captures a complete RDP port modification sequence executed via PowerShell and command prompt. The primary evidence includes:

**Registry Modification**: Sysmon EID 13 shows the direct registry write: `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` with the `PortNumber` value set to port 4489.

**Process Chain**: Security EID 4688 events capture the full command execution sequence:
- PowerShell spawning cmd.exe with command line: `"cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 4489 /f & netsh advfirewall firewall add rule name="RDPPORTLatest-TCP-In" dir=in action=allow protocol=TCP localport=4489`
- reg.exe execution: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 4489 /f`
- netsh.exe execution: `netsh advfirewall firewall add rule name="RDPPORTLatest-TCP-In" dir=in action=allow protocol=TCP localport=4489`

**Firewall Rule Creation**: Sysmon EID 13 captures the firewall rule registry entry: `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{5B97C5ED-979B-49B5-A7F1-25651F512130}` with details `v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4489|Name=RDPPORTLatest-TCP-In|`

**Sysmon Process Create Events**: EID 1 events show the execution of `whoami.exe`, `cmd.exe`, `reg.exe`, and `netsh.exe` with full command lines and process relationships.

## What This Dataset Does Not Contain

The dataset lacks evidence of the actual RDP service restart or configuration reload that would typically follow this registry modification. There are no service control events (sc.exe) or service restart notifications that would indicate the RDP service picked up the new port configuration.

No network connection events show RDP actually listening on the new port 4489, though this is expected since the test focuses on the configuration change rather than service verification.

The Sysmon configuration's include-mode filtering means some intermediate processes may not have generated ProcessCreate events, though the key administrative tools (reg.exe, netsh.exe) are properly captured due to their inclusion in suspicious process patterns.

## Assessment

This dataset provides excellent telemetry for detecting RDP port modification attacks. The combination of registry monitoring, process creation with command-line logging, and firewall rule tracking creates multiple detection opportunities with strong fidelity. The presence of both Sysmon and Security audit events provides redundancy and different perspectives on the same attack sequence.

The command-line arguments in Security EID 4688 events are particularly valuable, showing the exact registry keys, values, and firewall configuration being modified. The Sysmon registry events provide direct evidence of the configuration changes taking effect.

## Detection Opportunities Present in This Data

1. **Registry Key Modification Detection**: Monitor Sysmon EID 13 for writes to `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` with non-default values (anything other than 3389).

2. **Command Line Analysis**: Detect Security EID 4688 events where reg.exe modifies RDP registry keys, specifically looking for `reg add` commands targeting Terminal Server configuration paths.

3. **Firewall Rule Creation for RDP Ports**: Monitor Sysmon EID 13 registry writes to `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\*` where the rule details contain non-standard RDP ports (not 3389).

4. **Administrative Tool Process Chain**: Detect sequences where PowerShell or cmd.exe spawns both reg.exe and netsh.exe within a short timeframe, particularly when targeting RDP-related configurations.

5. **netsh Firewall Rule Addition**: Monitor Security EID 4688 for netsh.exe executions with command lines containing `advfirewall firewall add rule` and non-standard port numbers.

6. **Registry and Firewall Correlation**: Create detections that correlate RDP registry modifications (EID 13) with subsequent firewall rule additions for the same port number within a defined time window.

7. **Privilege Escalation Context**: Monitor for these activities occurring under SYSTEM context or elevated privileges, as RDP configuration changes require administrative access.
