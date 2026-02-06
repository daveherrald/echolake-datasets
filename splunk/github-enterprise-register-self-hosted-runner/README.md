# GitHub Enterprise Register Self Hosted Runner

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies when a self-hosted runner is created in GitHub Enterprise. The detection monitors GitHub Enterprise audit logs for actions related to creating new self-hosted runners at the organization or enterprise level. his behavior warrants monitoring because self-hosted runners execute workflow jobs on customer-controlled infrastructure, which could be exploited by attackers to execute malicious code, access sensitive data, or pivot to other systems. While self-hosted runners are a legitimate feature, their creation should be carefully controlled as compromised runners pose significant security risks. The impact includes potential remote code execution, data exfiltration, and lateral movement within the environment if a runner is compromised. SOC teams should investigate unexpected runner creation events to verify they are authorized and properly secured, especially if created by unfamiliar users or in unusual contexts.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/github_created_self_hosted_runner/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_enterprise_register_self_hosted_runner.yml)*
