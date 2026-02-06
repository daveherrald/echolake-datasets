# Cisco Duo Admin Login Unusual Browser

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies instances where a Duo admin logs in using a browser other than Chrome, which is considered unusual based on typical access patterns. Please adjust as needed to your environment. The detection leverages Duo activity logs ingested via the Cisco Security Cloud App and filters for admin login actions where the browser is not Chrome. By renaming and aggregating relevant fields such as user, browser, IP address, and location, the analytic highlights potentially suspicious access attempts that deviate from the norm. This behavior is significant for a SOC because the use of an unexpected browser may indicate credential compromise, session hijacking, or the use of unauthorized devices by attackers attempting to evade detection. Detecting such anomalies enables early investigation and response, helping to prevent privilege escalation, policy manipulation, or further compromise of sensitive administrative accounts. The impact of this attack could include unauthorized changes to security policies, user access, or the disabling of critical security controls, posing a substantial risk to the organizations security posture.

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

*Source: [Splunk Security Content](detections/application/cisco_duo_admin_login_unusual_browser.yml)*
