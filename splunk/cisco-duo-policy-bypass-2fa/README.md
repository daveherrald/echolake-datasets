# Cisco Duo Policy Bypass 2FA

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects instances where a Duo policy is created or updated to allow access without two-factor authentication (2FA). It identifies this behavior by searching Duo administrator activity logs for policy changes that set the authentication status to "Allow access without 2FA." By monitoring for these specific actions, the analytic highlights potential attempts to weaken authentication controls, which could be indicative of malicious activity or insider threats. This behavior is critical for a SOC to identify, as bypassing 2FA significantly reduces the security posture of an organization, making it easier for attackers to gain unauthorized access to sensitive systems and data. Detecting and responding to such policy changes promptly helps prevent potential account compromise and mitigates the risk of broader security breaches.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Cisco Duo Suspicious Activity

## Data Sources

- Cisco Duo Administrator

## Sample Data

- **Source:** duo
  **Sourcetype:** cisco:duo:administrator
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/cisco_duo_policy_bypass_2FA/cisco_duo_administrator.json


---

*Source: [Splunk Security Content](detections/application/cisco_duo_policy_bypass_2fa.yml)*
