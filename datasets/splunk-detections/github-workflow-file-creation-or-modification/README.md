# GitHub Workflow File Creation or Modification

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for hunting for any creations or modifications to GitHub Actions workflow YAML files across the organization's Linux or Windows endpoints.
This hunting query tracks all workflow file activity under .github/workflows directories to help defenders establish baselines of legitimate CI/CD workflow creation patterns, identify unusual or unauthorized changes, and detect anomalies that may indicate supply chain compromise.
GitHub Actions workflows execute with privileged access to secrets and deployment credentials, making them high-value targets for attackers.
By monitoring workflow file modifications over time, defenders can identify suspicious patterns such as unexpected workflow creation on developer workstations, modifications outside normal change windows, or activity in repositories that don't typically contain workflows.
This data is essential for detecting supply chain attacks like Shai-Hulud that inject malicious workflows across multiple repositories.


## MITRE ATT&CK

- T1574.006
- T1554
- T1195

## Analytic Stories

- NPM Supply Chain Compromise

## Data Sources

- Sysmon for Linux EventID 11
- Sysmon EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/npm/workflow_yml_sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/npm/windows_workflow_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/github_workflow_file_creation_or_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
