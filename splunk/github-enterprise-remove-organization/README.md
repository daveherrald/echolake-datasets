# GitHub Enterprise Remove Organization

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a user removes an organization from GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for organization deletion events, which could indicate unauthorized removal of critical business resources. For a SOC, identifying organization removals is crucial as it may signal account compromise, insider threats, or malicious attempts to disrupt business operations by deleting entire organizational structures. The impact could be severe, potentially resulting in loss of source code, repositories, team structures, access controls, and other critical organizational assets. This disruption could halt development workflows, cause data loss, and require significant effort to restore from backups if available. Additionally, unauthorized organization removal could be part of a larger attack campaign aimed at destroying or compromising enterprise assets.

## MITRE ATT&CK

- T1485
- T1195

## Analytic Stories

- GitHub Malicious Activity

## Data Sources

- GitHub Enterprise Audit Logs

## Sample Data

- **Source:** http:github
  **Sourcetype:** httpevent
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/github_remove_organization/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_remove_organization.yml)*
