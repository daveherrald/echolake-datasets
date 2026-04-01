# Cisco Isovalent - Shell Execution

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the execution of a shell inside a container namespace within the Cisco Isovalent environment. It identifies this activity by monitoring process execution logs for the execution of a shell (sh or bash) inside a container namespace. This behavior is significant for a SOC as it could allow an attacker to gain shell access to the container, potentially leading to further compromise of the Kubernetes cluster. If confirmed malicious, this activity could lead to data theft, service disruption, privilege escalation, lateral movement, and further attacks, severely compromising the cluster's security and integrity.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
