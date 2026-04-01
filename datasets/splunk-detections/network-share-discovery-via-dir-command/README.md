# Network Share Discovery Via Dir Command

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting access to Windows administrative SMB shares (Admin$, IPC$, C$) using the 'dir' command. It leverages Windows Security Event Logs with EventCode 5140 to identify this activity. This behavior is significant as it is commonly used by tools like PsExec/PaExec for staging binaries before creating and starting services on remote endpoints, a technique often employed by adversaries for lateral movement and remote code execution. If confirmed malicious, this activity could allow attackers to propagate malware, such as IcedID, across the network, leading to widespread infection and potential data breaches.

## MITRE ATT&CK

- T1135

## Analytic Stories

- IcedID

## Data Sources

- Windows Event Log Security 5140

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1135/net_share_discovery_via_dir/smb_access_security_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/network_share_discovery_via_dir_command.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
