# Cisco Duo Policy Skip 2FA for Other Countries

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when a Duo policy is created or updated to allow access without two-factor authentication (2FA) 
for users in countries other than the default. It identifies this behavior by searching Duo administrator activity logs for policy 
creation or update actions where the policy description indicates that access is permitted without 2FA for certain user locations. 
This is achieved by parsing the relevant fields in the logs and filtering for the specific condition of 'Allow access without 2FA.'
This behavior is significant for a Security Operations Center (SOC) because bypassing 2FA for any user group or location weakens 
the organization's security posture and increases the risk of unauthorized access. Attackers or malicious insiders may exploit 
such policy changes to circumvent strong authentication controls, potentially leading to account compromise, data breaches, or 
lateral movement within the environment. Early detection of these policy modifications enables the SOC to investigate and respond 
before attackers can leverage the weakened controls, thereby reducing the risk and impact of a successful attack.


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_bypass_2FA_other_countries/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_skip_2fa_for_other_countries.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
