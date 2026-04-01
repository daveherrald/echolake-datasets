# Vbscript Execution Using Wscript App

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of VBScript using the wscript.exe application. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant because wscript.exe is typically not used to execute VBScript, which is usually associated with cscript.exe. This deviation can indicate an attempt to evade traditional process monitoring and antivirus defenses. If confirmed malicious, this technique could allow attackers to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1059.005

## Analytic Stories

- FIN7
- Remcos
- AsyncRAT

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/vbscript_execution_using_wscript_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
