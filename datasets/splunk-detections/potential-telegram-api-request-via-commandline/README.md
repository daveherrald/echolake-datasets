# Potential Telegram API Request Via CommandLine

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk, Zaki Zarkasih Al Mustafa

## Description

This dataset contains sample data for detecting the presence of "api.telegram.org" in the CommandLine of a process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity can be significant as the telegram API has been used as an exfiltration mechanism or even as a C2 channel. If confirmed malicious, this could allow an attacker or malware to exfiltrate data or receive additional C2 instruction, potentially leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1102.002
- T1041

## Analytic Stories

- XMRig
- Water Gamayun
- 0bj3ctivity Stealer
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1102.002/telegram_api_cli/telegram_cli.log


---

*Source: [Splunk Security Content](detections/endpoint/potential_telegram_api_request_via_commandline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
