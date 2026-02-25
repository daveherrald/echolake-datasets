# Nginx ConnectWise ScreenConnect Authentication Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting attempts to exploit the ConnectWise ScreenConnect CVE-2024-1709 vulnerability, which allows attackers to bypass authentication via alternate paths or channels. It leverages Nginx access logs to identify web requests to the SetupWizard.aspx page, indicating potential exploitation. This activity is significant as it can lead to unauthorized administrative access and remote code execution. If confirmed malicious, attackers could create administrative users and gain full control over the affected ScreenConnect instance, posing severe security risks. Immediate remediation by updating to version 23.9.8 or above is recommended.

## MITRE ATT&CK

- T1190

## Analytic Stories

- ConnectWise ScreenConnect Vulnerabilities
- Seashell Blizzard
- Scattered Lapsus$ Hunters
- Hellcat Ransomware

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx:plus:kv
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/screenconnect/nginx_screenconnect.log


---

*Source: [Splunk Security Content](detections/web/nginx_connectwise_screenconnect_authentication_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
