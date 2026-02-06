# Windows Modify Registry UpdateServiceUrlAlternate

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious modification to the Windows Update configuration registry key, specifically targeting the UpdateServiceUrlAlternate setting. It leverages data from the Endpoint.Registry datamodel to identify changes to this registry path. This activity is significant because adversaries, including malware like RedLine Stealer, exploit this technique to bypass detection and deploy additional payloads. If confirmed malicious, this modification could allow attackers to redirect update services, potentially leading to the execution of malicious code, further system compromise, and persistent evasion of security defenses.

## MITRE ATT&CK

- T1112

## Analytic Stories

- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_updateserviceurlalternate.yml)*
