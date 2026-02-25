# ASL AWS Defense Evasion Impair Security Services

**Type:** Hunting

**Author:** Patrick Bareiss, Bhavin Patel, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the deletion of critical AWS Security Services configurations, such as CloudWatch alarms, GuardDuty detectors, and Web Application Firewall rules. It leverages Amazon Security Lake logs to identify specific API calls like "DeleteLogStream" and "DeleteDetector." This activity is significant because adversaries often use these actions to disable security monitoring and evade detection. If confirmed malicious, this could allow attackers to operate undetected, leading to potential data breaches, unauthorized access, and prolonged persistence within the AWS environment.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/aws_delete_security_services/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_defense_evasion_impair_security_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
