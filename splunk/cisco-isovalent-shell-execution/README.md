# Cisco Isovalent - Shell Execution

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the execution of a shell inside a container namespace within the Cisco Isovalent environment. It identifies this activity by monitoring process execution logs for the execution of a shell (sh or bash) inside a container namespace. This behavior is significant for a SOC as it could allow an attacker to gain shell access to the container, potentially leading to further compromise of the Kubernetes cluster. If confirmed malicious, this activity could lead to data theft, service disruption, privilege escalation, lateral movement, and further attacks, severely compromising the cluster's security and integrity.

## MITRE ATT&CK

- T1543

## Analytic Stories

- Cisco Isovalent Suspicious Activity

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___shell_execution.yml)*
