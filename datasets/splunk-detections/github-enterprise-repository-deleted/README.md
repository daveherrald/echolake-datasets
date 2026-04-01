# GitHub Enterprise Repository Deleted

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when a user deletes a repository in GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for repository deletion events, which could indicate unauthorized removal of critical source code and project resources. For a SOC, identifying repository deletions is crucial as it may signal account compromise, insider threats, or malicious attempts to destroy intellectual property and disrupt development operations. The impact could be severe, potentially resulting in permanent loss of source code, documentation, project history, and other critical assets if proper backups are not maintained. Repository deletion could halt development workflows, cause significant business disruption, and require substantial effort to restore from backups if available. Additionally, unauthorized repository removal could be part of a larger attack campaign aimed at destroying or compromising enterprise assets.

## MITRE ATT&CK

- T1485
- T1195

## Analytic Stories

- GitHub Malicious Activity
- NPM Supply Chain Compromise

## Data Sources

- GitHub Enterprise Audit Logs

## Sample Data

- **Source:** http:github
  **Sourcetype:** httpevent
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/github_delete_repository/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_repository_deleted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
