# Windows Steal Authentication Certificates Certificate Request

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting when a new certificate is requested from Certificate Services - AD CS. It leverages Event ID 4886, which indicates that a certificate request has been received. This activity is significant because unauthorized certificate requests can be part of credential theft or lateral movement tactics. If confirmed malicious, an attacker could use the certificate to impersonate users, gain unauthorized access to resources, or establish persistent access within the environment. Monitoring and correlating this event with other suspicious activities is crucial for identifying potential security incidents.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Windows Event Log Security 4886

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/4886_windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_certificate_request.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
