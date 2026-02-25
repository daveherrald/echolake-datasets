# Active Directory Lateral Movement Identified

**Type:** Correlation

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential lateral movement activities within an organization's Active Directory (AD) environment. It detects this activity by correlating multiple analytics from the Active Directory Lateral Movement analytic story within a specified time frame. This is significant for a SOC as lateral movement is a common tactic used by attackers to expand their access within a network, posing a substantial risk. If confirmed malicious, this activity could allow attackers to escalate privileges, access sensitive information, and persist within the environment, leading to severe security breaches.

## MITRE ATT&CK

- T1210

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources


## Sample Data

- **Source:** adlm
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/living_off_the_land/adlm_risk.log


---

*Source: [Splunk Security Content](detections/endpoint/active_directory_lateral_movement_identified.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
