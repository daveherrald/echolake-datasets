# Windows Credential Access From Browser Password Store

**Type:** Anomaly

**Author:** Teoderick Contreras, Bhavin Patel Splunk

## Description

This dataset contains sample data for identifying a possible non-common browser process accessing its browser user data profile. This tactic/technique has been observed in various Trojan Stealers, such as SnakeKeylogger, which attempt to gather sensitive browser information and credentials as part of their exfiltration strategy. Detecting this anomaly can serve as a valuable pivot for identifying processes that access lists of browser user data profiles unexpectedly. This detection uses a lookup file `browser_app_list` that maintains a list of well known browser applications and the browser paths that are allowed to access the browser user data profiles.

## MITRE ATT&CK

- T1012

## Analytic Stories

- StealC Stealer
- Salt Typhoon
- Earth Alux
- Quasar RAT
- PXA Stealer
- SnappyBee
- Malicious Inno Setup Loader
- Braodo Stealer
- MoonPeak
- Snake Keylogger
- China-Nexus Threat Activity
- Meduza Stealer
- Scattered Spider
- 0bj3ctivity Stealer
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/snakey_keylogger_outlook_reg_access/snakekeylogger_4663.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credential_access_from_browser_password_store.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
