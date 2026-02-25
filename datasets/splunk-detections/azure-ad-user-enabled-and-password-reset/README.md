# Azure AD User Enabled And Password Reset

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting an Azure AD user enabling a previously disabled account and resetting its password within 2 minutes. It uses Azure Active Directory events to identify this sequence of actions. This activity is significant because it may indicate an adversary with administrative access attempting to establish a backdoor identity within the Azure AD tenant. If confirmed malicious, this could allow the attacker to maintain persistent access, escalate privileges, and potentially exfiltrate sensitive information from the environment.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Azure Active Directory Persistence
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory Enable account
- Azure Active Directory Reset password (by admin)
- Azure Active Directory Update user

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/azure_ad_enable_and_reset/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_user_enabled_and_password_reset.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
