# Circle CI Disable Security Job

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the disabling of security jobs in CircleCI pipelines. It leverages CircleCI log data, renaming and extracting fields such as job names, workflow IDs, user information, commit messages, URLs, and branches. The detection identifies mandatory jobs for each workflow and checks if they were executed. This activity is significant because disabling security jobs can allow malicious code to bypass security checks, leading to potential data breaches, system downtime, and reputational damage. If confirmed malicious, this could result in unauthorized code execution and compromised pipeline integrity.

## MITRE ATT&CK

- T1554

## Analytic Stories

- Dev Sec Ops

## Data Sources

- CircleCI

## Sample Data

- **Source:** circleci
  **Sourcetype:** circleci
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_job/circle_ci_disable_security_job.json


---

*Source: [Splunk Security Content](detections/cloud/circle_ci_disable_security_job.yml)*
