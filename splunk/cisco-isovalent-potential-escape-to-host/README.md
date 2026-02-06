# Cisco Isovalent - Potential Escape to Host

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This analytic detects potential container escape or reconnaissance attempts by monitoring for the rapid execution of multiple suspicious Linux commands (nsenter, mount, ps aux, and ls) within a short time window. The search aggregates process execution logs into 5-minute buckets and identifies when two or more distinct commands occur in quick succession. This behavior is noteworthy because attackers often chain these commands together to pivot from a container into the host, enumerate processes, or browse filesystems. For a SOC, catching these clustered command executions is important because it highlights possible adversary activity attempting to break isolation and escalate privileges inside a Kubernetes environment.


## MITRE ATT&CK

- T1611

## Analytic Stories

- Cisco Isovalent Suspicious Activity
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1611/cisco_isovalent_k8_escape/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___potential_escape_to_host.yml)*
