# Windows Registry Certificate Added

**Type:** Anomaly

**Author:** Michael Haag, Teodeerick Contreras, Splunk

## Description

This dataset contains sample data for detecting the installation of a root CA certificate by monitoring specific registry paths for SetValue events. It leverages data from the Endpoint datamodel, focusing on registry paths containing "certificates" and registry values named "Blob." This activity is significant because unauthorized root CA certificates can compromise the integrity of encrypted communications and facilitate man-in-the-middle attacks. If confirmed malicious, this could allow an attacker to intercept, decrypt, or manipulate sensitive data, leading to severe security breaches.

## MITRE ATT&CK

- T1553.004

## Analytic Stories

- Windows Drivers
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1587.002/atomic_red_team/certblob_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_certificate_added.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
