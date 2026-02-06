# Cisco Isovalent - Late Process Execution

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

Detects process executions that occur well after a container has initialized, which can indicate
suspicious activity (e.g., interactive shells, injected binaries, or post-compromise tooling).
The analytic compares the process start time to the container start time and flags processes
launched more than 5 minutes (300 seconds) after initialization.


## MITRE ATT&CK

- T1543

## Analytic Stories

- Cisco Isovalent Suspicious Activity

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent_process_exec_delayed_shell.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___late_process_execution.yml)*
