# ASL AWS Defense Evasion Delete Cloudtrail

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects AWS `DeleteTrail` events within CloudTrail logs. It leverages Amazon Security Lake logs parsed in the Open Cybersecurity Schema Framework (OCSF) format to identify when a CloudTrail is deleted. This activity is significant because adversaries may delete CloudTrail logs to evade detection and operate with stealth. If confirmed malicious, this action could allow attackers to cover their tracks, making it difficult to trace their activities and investigate other potential compromises within the AWS environment.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_defense_evasion_delete_cloudtrail.yml)*
