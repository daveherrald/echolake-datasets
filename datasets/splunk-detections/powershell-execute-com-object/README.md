# Powershell Execute COM Object

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a COM CLSID through PowerShell. It leverages EventCode 4104 and searches for specific script block text indicating the creation of a COM object. This activity is significant as it is commonly used by adversaries and malware, such as the Conti ransomware, to execute commands, potentially for privilege escalation or bypassing User Account Control (UAC). If confirmed malicious, this technique could allow attackers to gain elevated privileges or persist within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1059.001
- T1546.015

## Analytic Stories

- Ransomware
- Malicious PowerShell
- Hermetic Wiper
- Data Destruction

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.015/pwh_com_object/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_execute_com_object.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
