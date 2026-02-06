# Cisco Duo Bulk Policy Deletion

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects instances where a Duo administrator performs a bulk deletion of more than three policies in a single action. It identifies this behavior by searching Duo activity logs for the policy_bulk_delete action, extracting the names of deleted policies, and counting them. If the count exceeds three, the event is flagged. This behavior is significant for a Security Operations Center (SOC) because mass deletion of security policies can indicate malicious activity, such as an attacker or rogue administrator attempting to weaken or disable security controls, potentially paving the way for further compromise. Detecting and investigating such actions promptly is critical, as the impact of this attack could include reduced security posture, increased risk of unauthorized access, and potential data breaches. Monitoring for bulk policy deletions helps ensure that any suspicious or unauthorized changes to security configurations are quickly identified and addressed to protect organizational assets and maintain compliance.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_bulk_policy_deletion/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_bulk_policy_deletion.yml)*
