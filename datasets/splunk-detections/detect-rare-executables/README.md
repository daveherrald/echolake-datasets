# Detect Rare Executables

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the execution of rare processes that appear only once across the network within a specified timeframe.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs.
This activity is significant for a SOC as it helps identify potentially malicious activities or unauthorized software, which could indicate a security breach or ongoing attack.
If confirmed malicious, such rare processes could lead to data theft, privilege escalation, or complete system compromise, making early detection crucial for minimizing impact.
The search currently identifies processes executed on fewer than 10 hosts, but this threshold can be adjusted based on the organization's environment and risk tolerance.
The search groups results by process name which can lead to blind spots if a malicious process uses a common name. To mitigate this, consider enhancing the detection logic to group by additional attributes such as process hash.


## MITRE ATT&CK

- T1204

## Analytic Stories

- China-Nexus Threat Activity
- Unusual Processes
- SnappyBee
- Salt Typhoon
- Rhysida Ransomware
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/rare_executables/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_rare_executables.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
