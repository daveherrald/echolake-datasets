# High Number of Login Failures from a single source

**Type:** Anomaly

**Author:** Bhavin Patel, Mauricio Velazco, Splunk

## Description

The following analytic detects multiple failed login attempts in Office365 Azure Active Directory from a single source IP address. It leverages Office365 management activity logs, specifically AzureActiveDirectoryStsLogon records, aggregating these logs in 5-minute intervals to count failed login attempts. This activity is significant as it may indicate brute-force attacks or password spraying, which are critical to monitor. If confirmed malicious, an attacker could gain unauthorized access to Office365 accounts, leading to potential data breaches, lateral movement within the organization, or further malicious activities using the compromised account.

## MITRE ATT&CK

- T1110.001

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365 UserLoginFailed

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/o365_high_number_authentications_for_user/o365_high_number_authentications_for_user.log


---

*Source: [Splunk Security Content](detections/cloud/high_number_of_login_failures_from_a_single_source.yml)*
