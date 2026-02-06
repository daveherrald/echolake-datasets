# ConnectWise ScreenConnect Authentication Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to exploit the ConnectWise ScreenConnect CVE-2024-1709 vulnerability, which allows attackers to bypass authentication via an alternate path or channel. It leverages web request logs to identify access to the SetupWizard.aspx page, indicating potential exploitation. This activity is significant as it can lead to unauthorized administrative access and remote code execution. If confirmed malicious, attackers could create administrative users and gain full control over the affected system, posing severe security risks. Immediate remediation by updating to version 23.9.8 or above is recommended.

## MITRE ATT&CK

- T1190

## Analytic Stories

- ConnectWise ScreenConnect Vulnerabilities
- Seashell Blizzard

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/screenconnect/connectwise_auth_suricata.log


---

*Source: [Splunk Security Content](detections/web/connectwise_screenconnect_authentication_bypass.yml)*
