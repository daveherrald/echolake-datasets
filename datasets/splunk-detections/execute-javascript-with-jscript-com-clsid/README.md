# Execute Javascript With Jscript COM CLSID

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of JavaScript using the JScript.Encode CLSID (COM Object) by cscript.exe. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line executions, and parent processes. This activity is significant as it is a known technique used by ransomware, such as Reddot, to execute malicious scripts and potentially disable AMSI (Antimalware Scan Interface). If confirmed malicious, this behavior could allow attackers to execute arbitrary code, evade detection, and maintain persistence within the environment.

## MITRE ATT&CK

- T1059.005

## Analytic Stories

- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/execute_javascript_with_jscript_com_clsid.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
