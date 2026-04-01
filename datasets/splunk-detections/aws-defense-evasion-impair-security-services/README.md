# AWS Defense Evasion Impair Security Services

**Type:** TTP

**Author:** Bhavin Patel, Gowthamaraj Rajendran, Splunk, PashFW, Github Community

## Description

This dataset contains sample data for detecting attempts to impair or disable AWS security services by monitoring specific deletion operations across GuardDuty, AWS WAF (classic and v2), CloudWatch, Route 53, and CloudWatch Logs. These actions include deleting detectors, rule groups, IP sets, web ACLs, logging configurations, alarms, and log streams. Adversaries may perform such operations to evade detection or remove visibility from defenders. By explicitly pairing eventName values with their corresponding eventSource services, this detection reduces noise and ensures that only security-related deletions are flagged. It leverages CloudTrail logs to identify specific API calls like "DeleteLogStream" and "DeleteDetector." This activity is significant because it indicates potential efforts to disable security monitoring and evade detection. If confirmed malicious, this could allow attackers to operate undetected, escalate privileges, or exfiltrate data without triggering security alerts, severely compromising the security posture of the AWS environment.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- AWS CloudTrail DeleteLogStream
- AWS CloudTrail DeleteDetector
- AWS CloudTrail DeleteIPSet
- AWS CloudTrail DeleteWebACL
- AWS CloudTrail DeleteRule
- AWS CloudTrail DeleteRuleGroup
- AWS CloudTrail DeleteLoggingConfiguration
- AWS CloudTrail DeleteAlarms

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/aws_delete_security_services/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_defense_evasion_impair_security_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
