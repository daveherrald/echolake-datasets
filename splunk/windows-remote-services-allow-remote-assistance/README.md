# Windows Remote Services Allow Remote Assistance

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications in the Windows registry to enable remote desktop assistance on a targeted machine. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the "Control\\Terminal Server\\fAllowToGetHelp" registry path. This activity is significant because enabling remote assistance via registry is uncommon and often associated with adversaries or malware like Azorult. If confirmed malicious, this could allow an attacker to remotely access and control the compromised host, leading to potential data exfiltration or further system compromise.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_services_allow_remote_assistance.yml)*
