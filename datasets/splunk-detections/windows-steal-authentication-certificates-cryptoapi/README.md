# Windows Steal Authentication Certificates CryptoAPI

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the extraction of authentication certificates using Windows Event Log - CAPI2 (CryptoAPI 2). It leverages EventID 70, which is generated when a certificate's private key is acquired. This detection is significant because it can identify potential misuse of certificates, such as those extracted by tools like Mimikatz or Cobalt Strike. If confirmed malicious, this activity could allow attackers to impersonate users, escalate privileges, or access sensitive information, posing a severe risk to the organization's security.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services
- Hellcat Ransomware

## Data Sources

- Windows Event Log CAPI2 70

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-CAPI2/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/capi2-operational.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_cryptoapi.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
