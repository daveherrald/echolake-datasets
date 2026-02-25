# Enable RDP In Other Port Number

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting modifications to the registry that enable RDP on a machine using a non-default port number. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the registry path "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" and the "PortNumber" value. This activity is significant as attackers often modify RDP settings to facilitate lateral movement and maintain remote access to compromised systems. If confirmed malicious, this could allow attackers to bypass network defenses, gain persistent access, and potentially control the compromised machine.

## MITRE ATT&CK

- T1021

## Analytic Stories

- Prohibited Traffic Allowed or Protocol Mismatch
- Windows Registry Abuse
- Windows RDP Artifacts and Defense Evasion
- Interlock Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/enable_rdp_in_other_port_number.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
