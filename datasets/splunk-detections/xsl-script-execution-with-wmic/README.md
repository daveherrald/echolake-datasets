# XSL Script Execution With WMIC

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of an XSL script using the WMIC process, which is often indicative of malicious activity. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving WMIC and XSL files. This behavior is significant as it has been associated with the FIN7 group, known for using this technique to execute malicious scripts. If confirmed malicious, this activity could allow attackers to execute arbitrary code, potentially leading to system compromise and further malicious actions within the environment.

## MITRE ATT&CK

- T1220

## Analytic Stories

- FIN7
- Suspicious WMI Use

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/xsl_script_execution_with_wmic.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
