# Windows DNS Query Request by Telegram Bot API

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a DNS query by a process to the associated Telegram API domain, which could indicate access via a Telegram bot commonly used by malware for command and control (C2) communications. By monitoring DNS queries related to Telegram's infrastructure, the detection identifies potential attempts to establish covert communication channels between a compromised system and external malicious actors. This behavior is often observed in cyberattacks where Telegram bots are used to receive commands or exfiltrate data, making it a key indicator of suspicious or malicious activity within a network.

## MITRE ATT&CK

- T1071.004
- T1102.002

## Analytic Stories

- Crypto Stealer
- 0bj3ctivity Stealer

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1102.002/telegram_api_dns/telegram_dns.log


---

*Source: [Splunk Security Content](detections/network/windows_dns_query_request_by_telegram_bot_api.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
