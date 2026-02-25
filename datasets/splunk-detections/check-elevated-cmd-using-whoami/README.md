# Check Elevated CMD using whoami

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of the "whoami" command with the "/group" flag, where the results are passed to the "find" command in order to look for a the string "12288". This string represents the SID of the group "Mandatory Label\High Mandatory Level" effectively checking if the current process is running as a "High" integrity process or with Administrator privileges. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant because it is commonly used by attackers, such as FIN7, to perform reconnaissance on a compromised host. If confirmed malicious, this behavior could indicate an attacker is assessing their privilege level, potentially leading to further privilege escalation or persistence within the environment.

## MITRE ATT&CK

- T1033

## Analytic Stories

- FIN7

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_js_2/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/check_elevated_cmd_using_whoami.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
