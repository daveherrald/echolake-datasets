# Windows Disable or Modify Tools Via Taskkill

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the use of taskkill.exe to forcibly terminate processes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include specific taskkill parameters. This activity is significant because it can indicate attempts to disable security tools or disrupt legitimate applications, a common tactic in malware operations. If confirmed malicious, this behavior could allow attackers to evade detection, disrupt system stability, and potentially gain further control over the compromised system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- PXA Stealer
- NjRAT
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/taskkill/taskkill_im.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_or_modify_tools_via_taskkill.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
