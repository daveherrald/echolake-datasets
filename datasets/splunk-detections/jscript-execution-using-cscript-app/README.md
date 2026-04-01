# Jscript Execution Using Cscript App

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of JScript using the cscript.exe process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This behavior is significant because JScript files are typically executed by wscript.exe, making cscript.exe execution unusual and potentially indicative of malicious activity, such as the FIN7 group's tactics. If confirmed malicious, this activity could allow attackers to execute arbitrary scripts, leading to code execution, data exfiltration, or further system compromise.

## MITRE ATT&CK

- T1059.007

## Analytic Stories

- FIN7
- Remcos

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/jscript_execution_using_cscript_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
