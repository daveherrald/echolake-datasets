# ASL AWS Defense Evasion Stop Logging Cloudtrail

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting `StopLogging` events within AWS CloudTrail logs, a critical action that adversaries may use to evade detection. By halting the logging of their malicious activities, attackers aim to operate undetected within a compromised AWS environment. This detection is achieved by monitoring for specific CloudTrail log entries that indicate the cessation of logging activities. Identifying such behavior is crucial for a Security Operations Center (SOC), as it signals an attempt to undermine the integrity of logging mechanisms, potentially allowing malicious activities to proceed without observation. The impact of this evasion tactic is significant, as it can severely hamper incident response and forensic investigations by obscuring the attacker's actions.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/asl_ocsf_cloudtrail_2.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_defense_evasion_stop_logging_cloudtrail.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
