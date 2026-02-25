# Windows Non Discord App Access Discord LevelDB

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting non-Discord applications accessing the Discord LevelDB database. It leverages Windows Security Event logs, specifically event code 4663, to identify file access attempts to the LevelDB directory by processes other than Discord. This activity is significant as it may indicate attempts to steal Discord credentials or access sensitive user data. If confirmed malicious, this could lead to unauthorized access to user profiles, messages, and other critical information, potentially compromising the security and privacy of the affected users.

## MITRE ATT&CK

- T1012

## Analytic Stories

- StealC Stealer
- Snake Keylogger
- PXA Stealer

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/snakey_keylogger_outlook_reg_access/snakekeylogger_4663.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_non_discord_app_access_discord_leveldb.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
