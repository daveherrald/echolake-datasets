# Cisco Duo Policy Deny Access

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies instances where a Duo administrator creates or updates a policy to explicitly deny user access within the Duo environment. It detects this behavior by searching Duo administrator activity logs for policy creation or update actions where the authentication status is set to "Deny access." By correlating these events with user and admin details, the analytic highlights potential misuse or malicious changes to access policies. This behavior is critical for a SOC to monitor, as unauthorized or suspicious denial of access policies can indicate insider threats, account compromise, or attempts to disrupt legitimate user access. The impact of such an attack may include denial of service to critical accounts, disruption of business operations, or the masking of further malicious activity by preventing targeted users from accessing resources. Early detection enables rapid investigation and remediation to maintain organizational security and availability.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_deny_access/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_deny_access.yml)*
