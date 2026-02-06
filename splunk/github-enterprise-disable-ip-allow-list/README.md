# GitHub Enterprise Disable IP Allow List

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies when an IP allow list is disabled in GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for actions related to disabling IP allow lists at the organization or enterprise level. This behavior is concerning because IP allow lists are a critical security control that restricts access to GitHub Enterprise resources to only trusted IP addresses. When disabled, it could indicate an attacker attempting to bypass access controls to gain unauthorized access from untrusted networks. The impact includes potential exposure of sensitive code repositories and GitHub Enterprise resources to access from any IP address. SOC teams should investigate such events, especially if they were not pre-approved changes, as they may indicate compromise of admin credentials or malicious insider activity.

## MITRE ATT&CK

- T1562.001
- T1195

## Analytic Stories

- GitHub Malicious Activity

## Data Sources

- GitHub Enterprise Audit Logs

## Sample Data

- **Source:** http:github
  **Sourcetype:** httpevent
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/github_disable_ip_allow_list/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_disable_ip_allow_list.yml)*
