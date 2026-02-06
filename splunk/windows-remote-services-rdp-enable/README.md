# Windows Remote Services Rdp Enable

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications in the Windows registry to enable Remote Desktop Protocol (RDP) on a targeted machine. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the "fDenyTSConnections" registry value. This activity is significant as enabling RDP via registry is uncommon and often associated with adversaries or malware attempting to gain remote access. If confirmed malicious, this could allow attackers to remotely control the compromised host, potentially leading to further exploitation and lateral movement within the network.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Medusa Ransomware
- BlackSuit Ransomware
- Azorult
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_services_rdp_enable.yml)*
