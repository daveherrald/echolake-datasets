# Detect Certipy File Modifications

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the use of the Certipy tool to enumerate Active Directory Certificate Services (AD CS) environments by identifying unique file modifications. It leverages endpoint process and filesystem data to spot the creation of files with specific names or extensions associated with Certipy's information gathering and exfiltration activities. This activity is significant as it indicates potential reconnaissance and data exfiltration efforts by an attacker. If confirmed malicious, this could lead to unauthorized access to sensitive AD CS information, enabling further attacks or privilege escalation within the network.

## MITRE ATT&CK

- T1649
- T1560

## Analytic Stories

- Windows Certificate Services
- Data Exfiltration
- Ingress Tool Transfer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/certify_abuse/certify_esc1_abuse_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_certipy_file_modifications.yml)*
