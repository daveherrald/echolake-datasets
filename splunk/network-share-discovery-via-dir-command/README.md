# Network Share Discovery Via Dir Command

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects access to Windows administrative SMB shares (Admin$, IPC$, C$) using the 'dir' command. It leverages Windows Security Event Logs with EventCode 5140 to identify this activity. This behavior is significant as it is commonly used by tools like PsExec/PaExec for staging binaries before creating and starting services on remote endpoints, a technique often employed by adversaries for lateral movement and remote code execution. If confirmed malicious, this activity could allow attackers to propagate malware, such as IcedID, across the network, leading to widespread infection and potential data breaches.

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
