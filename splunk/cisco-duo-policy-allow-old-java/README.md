# Cisco Duo Policy Allow Old Java

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a Duo policy is created or updated to allow the use of outdated Java versions, which can introduce significant 
security risks. It works by searching Duo administrator activity logs for policy creation or update actions where the policy explicitly sets 
'java_remediation' to 'no remediation', indicating that no restrictions are enforced against old Java. The analytic aggregates relevant details 
such as the user, admin email, and action context for further investigation. Identifying this behavior is critical for a Security Operations Center 
(SOC) because allowing outdated Java can expose an organization to known vulnerabilities, malware, and exploitation techniques. Attackers or malicious 
insiders may attempt to weaken security controls by modifying policies to permit insecure software, increasing the risk of compromise. Prompt detection 
enables SOC analysts to respond quickly, revert risky changes, and mitigate potential threats before they are exploited.


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_allow_old_flash_and_java/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_allow_old_java.yml)*
