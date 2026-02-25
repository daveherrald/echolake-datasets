# O365 Bypass MFA via Trusted IP

**Type:** TTP

**Author:** Bhavin Patel, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where new IP addresses are added to the trusted IPs list in Office 365, potentially allowing users from these IPs to bypass Multi-Factor Authentication (MFA) during login. It leverages O365 audit logs, specifically focusing on events related to the modification of trusted IP settings. This activity is significant because adding trusted IPs can weaken the security posture by bypassing MFA, which is a critical security control. If confirmed malicious, this could lead to unauthorized access, compromising sensitive information and systems. Immediate investigation is required to validate the legitimacy of the IP addition.

## MITRE ATT&CK

- T1562.007

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Set Company Information.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/o365_bypass_mfa_via_trusted_ip/o365_bypass_mfa_via_trusted_ip.json


---

*Source: [Splunk Security Content](detections/cloud/o365_bypass_mfa_via_trusted_ip.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
