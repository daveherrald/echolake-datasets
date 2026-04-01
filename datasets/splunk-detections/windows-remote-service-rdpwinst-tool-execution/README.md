# Windows Remote Service Rdpwinst Tool Execution

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the RDPWInst.exe tool, which is an RDP wrapper library used to enable remote desktop host support and concurrent RDP sessions. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, original file names, and specific command-line arguments. This activity is significant because adversaries can abuse this tool to establish unauthorized RDP connections, facilitating remote access and potential lateral movement within the network. If confirmed malicious, this could lead to unauthorized access, data exfiltration, and further compromise of the targeted host.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Azorult
- Compromised Windows Host
- Windows RDP Artifacts and Defense Evasion
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_service_rdpwinst_tool_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
