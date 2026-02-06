# GitHub Organizations Repository Archived

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a repository is archived in GitHub Organizations. The detection monitors GitHub Organizations audit logs for repository archival events by tracking actor details, repository information, and associated metadata. For a SOC, identifying repository archival is important as it could indicate attempts to make critical code inaccessible or preparation for repository deletion. While archiving is a legitimate feature, unauthorized archival of active repositories could signal account compromise, insider threats, or attempts to disrupt development operations. The impact of unauthorized repository archival includes loss of active development access, disruption to workflows and CI/CD pipelines, and potential business delays if critical repositories are affected. Additionally, archived repositories may be targeted for subsequent deletion, potentially resulting in permanent loss of intellectual property if proper backups are not maintained.

## MITRE ATT&CK

- T1485
- T1195

## Analytic Stories

- GitHub Malicious Activity
- NPM Supply Chain Compromise

## Data Sources

- GitHub Organizations Audit Logs

## Sample Data

- **Source:** github
  **Sourcetype:** github:cloud:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/github_archived_repository/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_organizations_repository_archived.yml)*
