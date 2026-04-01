# Cisco Duo Admin Login Unusual Country

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting instances where a Duo admin login originates from a country outside of the United States, which may indicate suspicious or unauthorized access attempts. Please adjust as needed to your environment. It works by analyzing Duo activity logs for admin login actions and filtering out events where the access device's country is not within the expected region. By correlating user, device, browser, and location details, the analytic highlights anomalies in geographic login patterns. This behavior is critical for a SOC to identify because admin accounts have elevated privileges, and access from unusual countries can be a strong indicator of credential compromise, account takeover, or targeted attacks. Early detection of such activity enables rapid investigation and response, reducing the risk of unauthorized changes, data breaches, or further lateral movement within the environment. The impact of this attack can be severe, potentially allowing attackers to bypass security controls, alter configurations, or exfiltrate sensitive information.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Activity

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_unusual_admin_login/cisco_duo_activity.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_admin_login_unusual_country.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
