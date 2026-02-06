# Circle CI Disable Security Step

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the disablement of security steps in a CircleCI pipeline. It leverages CircleCI logs, using field renaming, joining, and statistical analysis to identify instances where mandatory security steps are not executed. This activity is significant because disabling security steps can introduce vulnerabilities, unauthorized changes, or malicious code into the pipeline. If confirmed malicious, this could lead to potential attacks, data breaches, or compromised infrastructure. Investigate by reviewing job names, commit details, and user information associated with the disablement, and examine any relevant artifacts and concurrent processes.

## MITRE ATT&CK

- T1554

## Analytic Stories

- Dev Sec Ops

## Data Sources

- CircleCI

## Sample Data

- **Source:** circleci
  **Sourcetype:** circleci
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_step/circle_ci_disable_security_step.json


---

*Source: [Splunk Security Content](detections/cloud/circle_ci_disable_security_step.yml)*
