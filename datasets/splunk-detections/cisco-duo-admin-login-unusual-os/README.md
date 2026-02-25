# Cisco Duo Admin Login Unusual Os

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifying Duo admin login attempts from operating systems that are unusual for your environment, excluding commonly used OS such as Mac OS X. Please adjust to your environment. It works by analyzing Duo activity logs for admin login actions and filtering out logins from expected operating systems. The analytic then aggregates events by browser, version, source IP, location, and OS details to highlight anomalies. Detecting admin logins from unexpected operating systems is critical for a SOC, as it may indicate credential compromise, unauthorized access, or attacker activity using unfamiliar devices. Such behavior can precede privilege escalation, policy changes, or other malicious actions within the Duo environment. Early detection enables rapid investigation and response, reducing the risk of account takeover and minimizing potential damage to organizational security controls.

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

*Source: [Splunk Security Content](detections/application/cisco_duo_admin_login_unusual_os.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
