# GitHub Organizations Delete Branch Ruleset

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when branch rulesets are deleted in GitHub Organizations. The detection monitors GitHub Organizations audit logs for branch ruleset deletion events by tracking actor details, repository information, and associated metadata. For a SOC, identifying deleted branch rulesets is critical as it could indicate attempts to bypass code review requirements and security controls. Branch rulesets are essential security controls that enforce code review, prevent force pushes, and maintain code quality. Disabling these protections could allow malicious actors to directly push unauthorized code changes or backdoors to protected branches. The impact of disabled branch protection includes potential code tampering, bypass of security reviews, introduction of vulnerabilities or malicious code, and compromise of software supply chain integrity. This activity could be part of a larger attack chain where an adversary first disables security controls before attempting to inject malicious code.

## MITRE ATT&CK

- T1562.001
- T1195

## Analytic Stories

- GitHub Malicious Activity
- NPM Supply Chain Compromise

## Data Sources

- GitHub Organizations Audit Logs

## Sample Data

- **Source:** github
  **Sourcetype:** github:cloud:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/github_delete_branch_ruleset/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_organizations_delete_branch_ruleset.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
