# GitHub Organizations Repository Deleted

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies when a repository is deleted within a GitHub organization. The detection monitors GitHub Organizations audit logs for repository deletion events by tracking actor details, repository information, and associated metadata. This behavior is concerning for SOC teams as malicious actors may attempt to delete repositories to destroy source code, intellectual property, or evidence of compromise. Repository deletion can result in permanent loss of code, documentation, and project history if proper backups are not maintained. Additionally, unauthorized repository deletion could indicate account compromise, insider threats, or attempts to disrupt business operations. The impact of a repository deletion attack includes loss of intellectual property, disruption to development workflows, and potential financial losses from lost work. Early detection of unauthorized repository deletions allows security teams to investigate potential compromises and restore from backups if needed.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/github_delete_repository/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_organizations_repository_deleted.yml)*
