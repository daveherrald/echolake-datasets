# Cisco Duo Bypass Code Generation

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when a Duo user generates a bypass code, which allows them to circumvent multi-factor authentication (2FA) protections. 
It works by monitoring Duo activity logs for the 'bypass_create' action, renaming the affected object as the user, and aggregating events to identify 
instances where a bypass code is issued. This behavior is significant for a Security Operations Center (SOC) because generating a bypass code can enable 
attackers, malicious insiders, or unauthorized administrators to gain access to sensitive systems without the required second authentication factor. 
Such activity may indicate account compromise, privilege abuse, or attempts to weaken security controls. Early detection of bypass code generation is 
critical, as it allows the SOC to investigate and respond before an attacker can exploit the reduced authentication requirements, helping to prevent 
unauthorized access, data breaches, or further lateral movement within the environment. Monitoring for this action helps maintain strong authentication 
standards and reduces the risk of credential-based attacks.


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_bypass_code/cisco_duo_activity.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_bypass_code_generation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
