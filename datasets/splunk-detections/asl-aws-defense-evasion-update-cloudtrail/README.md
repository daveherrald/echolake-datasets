# ASL AWS Defense Evasion Update Cloudtrail

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting `UpdateTrail` events within AWS CloudTrail logs, aiming to identify attempts by attackers to evade detection by altering logging configurations. By updating CloudTrail settings with incorrect parameters, such as changing multi-regional logging to a single region, attackers can impair the logging of their activities across other regions. This behavior is crucial for Security Operations Centers (SOCs) to identify, as it indicates an adversary's intent to operate undetected within a compromised AWS environment. The impact of such evasion tactics is significant, potentially allowing malicious activities to proceed without being logged, thereby hindering incident response and forensic investigations.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/update_cloudtrail/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_defense_evasion_update_cloudtrail.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
