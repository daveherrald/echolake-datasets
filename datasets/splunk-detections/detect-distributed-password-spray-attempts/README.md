# Detect Distributed Password Spray Attempts

**Type:** Hunting

**Author:** Dean Luxton

## Description

This analytic employs the 3-sigma approach to identify distributed password spray attacks. A distributed password spray attack is a type of brute force attack where the attacker attempts a few common passwords against many different accounts, connecting from multiple IP addresses to avoid detection. By utilizing the Authentication Data Model, this detection is effective for all CIM-mapped authentication events, providing comprehensive coverage and enhancing security against these attacks.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Compromised User Account
- Active Directory Password Spraying

## Data Sources

- Azure Active Directory Sign-in activity

## Sample Data

- **Source:** azure:monitor:aad
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/azure_ad_distributed_spray/azure_ad_distributed_spray.log


---

*Source: [Splunk Security Content](detections/application/detect_distributed_password_spray_attempts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
