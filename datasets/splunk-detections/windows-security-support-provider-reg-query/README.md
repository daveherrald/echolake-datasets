# Windows Security Support Provider Reg Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying command-line activity querying the registry for Security Support Providers (SSPs) related to Local Security Authority (LSA) protection and configuration. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on processes accessing specific LSA registry paths. Monitoring this activity is crucial as adversaries and post-exploitation tools like winpeas may use it to gather information on LSA protections, potentially leading to credential theft. If confirmed malicious, attackers could exploit this to scrape password hashes or plaintext passwords from memory, significantly compromising system security.

## MITRE ATT&CK

- T1547.005

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_security_support_provider_reg_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
