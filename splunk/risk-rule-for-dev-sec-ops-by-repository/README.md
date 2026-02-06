# Risk Rule for Dev Sec Ops by Repository

**Type:** Correlation

**Author:** Bhavin Patel

## Description

The following analytic identifies high-risk activities within repositories by correlating repository data with risk scores. It leverages findings and intermediate findings created by detections from the Dev Sec Ops analytic stories, summing risk scores and capturing source and user information. The detection focuses on high-risk scores above 100 and sources with more than three occurrences. This activity is significant as it highlights repositories frequently targeted by threats, providing insights into potential vulnerabilities. If confirmed malicious, attackers could exploit these repositories, leading to data breaches or infrastructure compromise.

## MITRE ATT&CK

- T1204.003

## Analytic Stories

- Dev Sec Ops

## Data Sources


## Sample Data

- **Source:** aws_ecr_risk_dataset.log
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.003/risk_dataset/aws_ecr_risk_dataset.log


---

*Source: [Splunk Security Content](detections/cloud/risk_rule_for_dev_sec_ops_by_repository.yml)*
