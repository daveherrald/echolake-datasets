# GitHub Enterprise Delete Branch Ruleset

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when branch rules are deleted in GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for branch rule deletion events by tracking actor details, repository information, and associated metadata. For a SOC, identifying deleted branch rules is critical as it could indicate attempts to bypass code review requirements and security controls. Branch deletion rules are essential security controls that enforce code review, prevent force pushes, and maintain code quality. Disabling these protections could allow malicious actors to directly push unauthorized code changes or backdoors to protected branches. The impact of disabled branch protection includes potential code tampering, bypass of security reviews, introduction of vulnerabilities or malicious code, and compromise of software supply chain integrity. This activity could be part of a larger attack chain where an adversary first disables security controls before attempting to inject malicious code.

## MITRE ATT&CK

- T1562.001
- T1195

## Analytic Stories

- GitHub Malicious Activity
- NPM Supply Chain Compromise

## Data Sources

- GitHub Enterprise Audit Logs

## Sample Data

- **Source:** http:github
  **Sourcetype:** httpevent
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/github_delete_branch_ruleset/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_delete_branch_ruleset.yml)*
