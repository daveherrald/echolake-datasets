# Windows Steal Authentication Certificates Certificate Issued

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the issuance of a new certificate by Certificate Services - AD CS, detected via Event ID 4887. This event logs the requester user context, DNS hostname of the requesting machine, and the request time. Monitoring this activity is crucial as it can indicate potential misuse of authentication certificates. If confirmed malicious, an attacker could use the issued certificate to impersonate users, escalate privileges, or maintain persistence within the environment. This detection helps in identifying and correlating suspicious certificate-related activities for further investigation.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Windows Event Log Security 4887

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/4887_windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_certificate_issued.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
