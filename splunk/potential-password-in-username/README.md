# Potential password in username

**Type:** Hunting

**Author:** Mikael Bjerkeland, Splunk

## Description

The following analytic identifies instances where users may have mistakenly entered their passwords in the username field during authentication attempts. It detects this by analyzing failed authentication events with usernames longer than 7 characters and high Shannon entropy, followed by a successful authentication from the same source to the same destination. This activity is significant as it can indicate potential security risks, such as password exposure. If confirmed malicious, attackers could exploit this to gain unauthorized access, leading to potential data breaches or further compromise of the system.

## MITRE ATT&CK

- T1078.003
- T1552.001

## Analytic Stories

- Credential Dumping
- Insider Threat

## Data Sources

- Linux Secure

## Sample Data

- **Source:** /var/log/secure
  **Sourcetype:** linux_secure
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/password_in_username/linux_secure.log


---

*Source: [Splunk Security Content](detections/endpoint/potential_password_in_username.yml)*
