# Kubernetes Cron Job Creation

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the creation of a Kubernetes cron job, which is a task scheduled to run automatically at specified intervals. It identifies this activity by monitoring Kubernetes Audit logs for the creation events of cron jobs. This behavior is significant for a SOC as it could allow an attacker to execute malicious tasks repeatedly and automatically, posing a threat to the Kubernetes infrastructure. If confirmed malicious, this activity could lead to persistent attacks, service disruptions, or unauthorized access to sensitive information.

## MITRE ATT&CK

- T1053.007

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_cron_job_creation.yml)*
