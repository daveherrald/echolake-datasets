# Cisco Secure Firewall - Remote Access Software Usage Traffic

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting network traffic associated with known remote access software applications
that are covered by Cisco Secure Firewall Application Detectors, such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer.
It leverages Cisco Secure Firewall Threat Defense Connection Event.
This activity is significant because adversaries often use remote access tools to maintain unauthorized access to compromised environments.
If confirmed malicious, this activity could allow attackers to control systems remotely, exfiltrate
data, or deploy additional malware, posing a severe threat to the organization's security.


## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- Remote Monitoring and Management Software
- Cisco Secure Firewall Threat Defense Analytics
- Scattered Spider
- Interlock Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___remote_access_software_usage_traffic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
