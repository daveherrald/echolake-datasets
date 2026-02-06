# Cisco Isovalent - Cron Job Creation

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the creation of a cron job within the Cisco Isovalent environment. It identifies this activity by monitoring process execution logs for cron job creation events. This behavior is significant for a SOC as it could allow an attacker to execute malicious tasks repeatedly and automatically, posing a threat to the Kubernetes infrastructure. If confirmed malicious, this activity could lead to persistent attacks, service disruptions, or unauthorized access to sensitive information.

## MITRE ATT&CK

- T1053.003
- T1053.007

## Analytic Stories

- Cisco Isovalent Suspicious Activity

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___cron_job_creation.yml)*
