# High Frequency Copy Of Files In Network Share

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a high frequency of file copying or moving within network shares, which may indicate potential data sabotage or exfiltration attempts. It leverages Windows Security Event Logs (EventCode 5145) to monitor access to specific file types and network shares. This activity is significant as it can reveal insider threats attempting to transfer classified or internal files, potentially leading to data breaches or evidence tampering. If confirmed malicious, this behavior could result in unauthorized data access, data loss, or compromised sensitive information.

## MITRE ATT&CK

- T1537

## Analytic Stories

- Information Sabotage
- Insider Threat
- Hellcat Ransomware

## Data Sources

- Windows Event Log Security 5145

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/high_frequency_copy_of_files_in_network_share/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/high_frequency_copy_of_files_in_network_share.yml)*
