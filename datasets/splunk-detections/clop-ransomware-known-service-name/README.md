# Clop Ransomware Known Service Name

**Type:** TTP

**Author:** Teoderick Contreras

## Description

This dataset contains sample data for identifying the creation of a service with a known name used by CLOP ransomware for persistence and high-privilege code execution. It detects this activity by monitoring Windows Event Logs (EventCode 7045) for specific service names ("SecurityCenterIBM", "WinCheckDRVs"). This activity is significant because the creation of such services is a common tactic used by ransomware to maintain control over infected systems. If confirmed malicious, this could allow attackers to execute code with elevated privileges, maintain persistence, and potentially disrupt or encrypt critical data.

## MITRE ATT&CK

- T1543

## Analytic Stories

- Compromised Windows Host
- Clop Ransomware

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/clop_ransomware_known_service_name.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
