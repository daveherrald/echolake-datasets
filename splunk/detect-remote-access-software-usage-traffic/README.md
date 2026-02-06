# Detect Remote Access Software Usage Traffic

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects network traffic associated with known remote access software applications, such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer. It leverages Palo Alto traffic logs mapped to the Network_Traffic data model in Splunk. This activity is significant because adversaries often use remote access tools to maintain unauthorized access to compromised environments. If confirmed malicious, this activity could allow attackers to control systems remotely, exfiltrate data, or deploy additional malware, posing a severe threat to the organization's security.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- Remote Monitoring and Management Software
- Scattered Spider
- Interlock Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Palo Alto Network Traffic

## Sample Data

- **Source:** screenconnect_palo_traffic
  **Sourcetype:** pan:traffic
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_palo_traffic.log


---

*Source: [Splunk Security Content](detections/network/detect_remote_access_software_usage_traffic.yml)*
