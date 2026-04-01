# Cisco Duo Set User Status to Bypass 2FA

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting instances where a Duo user's status is changed to "Bypass" for 2FA, specifically when the 
previous status was "Active." This behavior is identified by analyzing Duo activity logs for user update actions, extracting 
the status transitions, and filtering for cases where a user is set to bypass multi-factor authentication. This is a critical 
event for a Security Operations Center (SOC) to monitor, as bypassing 2FA significantly weakens account security and may 
indicate malicious insider activity or account compromise. Attackers or unauthorized administrators may exploit this change to 
disable strong authentication controls, increasing the risk of unauthorized access to sensitive systems and data. Early detection 
of such changes enables rapid investigation and response, helping to prevent potential breaches and limit the impact of 
credential-based attacks. 


## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_bypass_2FA/cisco_duo_activity.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_set_user_status_to_bypass_2fa.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
