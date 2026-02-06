# GitHub Organizations Disable Dependabot

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects when a user disables Dependabot security features within a GitHub repository. Dependabot helps automatically identify and fix security vulnerabilities in dependencies. The detection monitors GitHub Enterprise logs for configuration changes that disable Dependabot functionality. This behavior could indicate an attacker attempting to prevent the automatic detection of vulnerable dependencies, which would allow them to exploit known vulnerabilities that would otherwise be patched. For a SOC, identifying the disabling of security features like Dependabot is critical as it may be a precursor to supply chain attacks where attackers exploit vulnerable dependencies. The impact could be severe if vulnerabilities remain unpatched, potentially leading to code execution, data theft, or other compromises through the software supply chain.

## MITRE ATT&CK

- T1562.001
- T1195

## Analytic Stories

- GitHub Malicious Activity

## Data Sources

- GitHub Organizations Audit Logs

## Sample Data

- **Source:** github
  **Sourcetype:** github:cloud:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable_dependabot/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_organizations_disable_dependabot.yml)*
