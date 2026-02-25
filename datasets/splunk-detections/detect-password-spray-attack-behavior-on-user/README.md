# Detect Password Spray Attack Behavior On User

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying any user failing to authenticate from 10 or more unique sources. This behavior could represent an adversary performing a Password Spraying attack to obtain initial access or elevate privileges. This logic can be used for real time security monitoring as well as threat hunting exercises. Environments can be very different depending on the organization. Test and customize this detections thresholds as needed

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Compromised User Account
- Crypto Stealer

## Data Sources

- Windows Event Log Security 4624
- Windows Event Log Security 4625

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/generic_password_spray/password_spray_attack.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_password_spray_attack_behavior_on_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
