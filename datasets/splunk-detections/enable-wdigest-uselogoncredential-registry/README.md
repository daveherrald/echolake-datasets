# Enable WDigest UseLogonCredential Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting a suspicious registry modification that enables the plain text credential feature in Windows by setting the "UseLogonCredential" value to 1 in the WDigest registry path. This detection leverages data from the Endpoint.Registry data model, focusing on specific registry paths and values. This activity is significant because it is commonly used by malware and tools like Mimikatz to dump plain text credentials, indicating a potential credential dumping attempt. If confirmed malicious, this could allow an attacker to obtain sensitive credentials, leading to further compromise and lateral movement within the network.

## MITRE ATT&CK

- T1112
- T1003

## Analytic Stories

- Credential Dumping
- Windows Registry Abuse
- CISA AA22-320A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/atomic_red_team/wdigest_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/enable_wdigest_uselogoncredential_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
