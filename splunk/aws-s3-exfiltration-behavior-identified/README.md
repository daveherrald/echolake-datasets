# AWS S3 Exfiltration Behavior Identified

**Type:** Correlation

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies potential AWS S3 exfiltration behavior by correlating multiple risk events related to Collection and Exfiltration techniques. It leverages risk events from AWS sources, focusing on instances where two or more unique analytics and distinct MITRE ATT&CK IDs are triggered for a specific risk object. This activity is significant as it may indicate an ongoing data exfiltration attempt, which is critical for security teams to monitor. If confirmed malicious, this could lead to unauthorized access and theft of sensitive information, compromising the organization's data integrity and confidentiality.

## MITRE ATT&CK

- T1537

## Analytic Stories

- Suspicious Cloud Instance Activities
- Data Exfiltration

## Data Sources


## Sample Data

- **Source:** aws_exfil
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_exfil_risk_events/aws_risk.log


---

*Source: [Splunk Security Content](detections/cloud/aws_s3_exfiltration_behavior_identified.yml)*
