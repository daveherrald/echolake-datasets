# GitHub Enterprise Repository Archived

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when a repository is archived in GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for repository archival events by tracking actor details, repository information, and associated metadata. For a SOC, identifying repository archival is important as it could indicate attempts to make critical code inaccessible or preparation for repository deletion. While archiving is a legitimate feature, unauthorized archival of active repositories could signal account compromise, insider threats, or attempts to disrupt development operations. The impact of unauthorized repository archival includes loss of active development access, disruption to workflows and CI/CD pipelines, and potential business delays if critical repositories are affected. Additionally, archived repositories may be targeted for subsequent deletion, potentially resulting in permanent loss of intellectual property if proper backups are not maintained.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/github_archived_repository/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_repository_archived.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
