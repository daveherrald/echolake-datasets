# T1040-7: Network Sniffing — Windows Internal pktmon set filter

## Technique Context

T1040 Network Sniffing involves capturing network traffic to obtain sensitive information like credentials or business-critical data. The detection community focuses heavily on this technique because it can provide attackers with plaintext credentials, lateral movement opportunities, and sensitive data exfiltration paths. This specific test (T1040-7) targets Windows' built-in `pktmon` utility, which was introduced in Windows 10 version 1809 and Windows Server 2019 as Microsoft's native packet monitoring tool.

The `pktmon` utility is particularly concerning from a detection perspective because it's a legitimate Microsoft-signed binary that can capture network packets without requiring third-party tools or administrative installation of packet capture drivers. Attackers leverage pktmon for its stealth characteristics—it doesn't require additional software installation and blends in with legitimate network troubleshooting activities. The detection community emphasizes monitoring pktmon usage because it represents a significant shift from traditional network sniffing that required tools like Wireshark or tcpdump.

## What This Dataset Contains

This dataset appears to be **mislabeled or contains an execution error**. Despite being tagged as T1040-7 (Network Sniffing with pktmon), the actual telemetry shows completely different activities:

**Security Event Log (EID 4688/4689)**: Shows process creation for `whoami.exe`, `cmd.exe`, `reg.exe`, `netsh.exe`, and `net.exe` - but **no pktmon.exe execution**. The command lines reveal RDP port modification activities: `"cmd.exe" /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 4489 /f & netsh advfirewall firewall add rule name="RDPPORTLatest-TCP-In" dir=in action=allow protocol=TCP localport=4489` and later cleanup commands restoring port 3389.

**Sysmon Events**: Multiple PowerShell process creations (EID 1) showing `powershell.exe` executions, but the key Sysmon EID 1 events show `whoami.exe` (system discovery), `reg.exe` (registry modification), and `netsh.exe` (firewall manipulation) - activities consistent with RDP configuration changes, not network sniffing.

**PowerShell Operational Log (EID 4103/4104)**: Contains only test framework boilerplate with `Set-ExecutionPolicy Bypass` commands and error handling scriptblocks. No PowerShell commands related to pktmon or network packet capture are present.

**Registry Activity (Sysmon EID 13)**: Shows firewall rule creation in `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{...}` with details `"v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4489|Name=RDPPORTLatest-TCP-In|"`.

## What This Dataset Does Not Contain

This dataset is **missing all T1040 Network Sniffing telemetry**:

- **No pktmon.exe process creation**: No Sysmon EID 1 events or Security EID 4688 events showing pktmon execution
- **No pktmon command-line arguments**: No evidence of `pktmon filter add`, `pktmon start`, or `pktmon stop` commands
- **No packet capture file creation**: No Sysmon EID 11 file creation events for .etl or .pcap files
- **No network monitoring activity**: No events indicating packet interception or network interface monitoring
- **No ETW provider registration**: Missing telemetry that would indicate pktmon registering with Event Tracing for Windows

Instead, the dataset contains telemetry consistent with **T1021.001 Remote Desktop Protocol** or similar RDP-related techniques involving port manipulation and firewall rule modifications.

## Assessment

This dataset has **minimal utility for T1040 detection engineering** due to the apparent mislabeling or test execution failure. The telemetry captured is entirely unrelated to network sniffing activities and instead documents RDP port configuration changes. 

For legitimate T1040 detection engineering, this dataset would need to contain:
- Pktmon process execution with command-line parameters
- ETL file creation and manipulation events  
- Network interface enumeration activities
- Potential packet processing or filtering operations

The data quality is good for the activities it does capture (RDP configuration), with comprehensive process creation, registry modification, and firewall rule telemetry across Security, Sysmon, and PowerShell logs. However, this represents a fundamental mismatch between the stated technique and captured activities.

## Detection Opportunities Present in This Data

Given the actual content, this dataset supports detection opportunities for **RDP configuration manipulation** rather than network sniffing:

1. **RDP Port Modification Detection**: Monitor registry writes to `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` with non-standard port values (Security EID 4657 or Sysmon EID 13)

2. **Firewall Rule Creation for Non-Standard RDP Ports**: Alert on netsh.exe executions adding firewall rules for ports other than 3389, particularly with names like "RDPPORTLatest-TCP-In"

3. **Coordinated RDP Service Manipulation**: Detect sequences of reg.exe (port change), netsh.exe (firewall rule), and net.exe (service restart) within short time windows

4. **PowerShell Execution Policy Bypass**: Monitor EID 4103 events showing Set-ExecutionPolicy with Bypass parameter, especially in system context

5. **System Discovery via whoami.exe**: Track whoami.exe executions from PowerShell parent processes as potential reconnaissance activity
