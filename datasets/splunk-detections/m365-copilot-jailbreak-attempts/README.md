# M365 Copilot Jailbreak Attempts

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects M365 Copilot jailbreak attempts through prompt injection techniques including rule manipulation, system bypass commands, and AI impersonation requests that attempt to circumvent built-in safety controls. The detection searches exported eDiscovery prompt logs for jailbreak keywords like "pretend you are," "act as," "rules=," "ignore," "bypass," and "override" in the Subject_Title field, assigning severity scores based on the manipulation type (score of 4 for amoral impersonation or explicit rule injection, score of 3 for entity roleplay or bypass commands). Prompts with a jailbreak score of 2 or higher are flagged, prioritizing the most severe attempts to override AI safety mechanisms through direct instruction injection or unauthorized persona adoption.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Suspicious Microsoft 365 Copilot Activities

## Data Sources

- M365 Exported eDiscovery Prompts

## Sample Data

- **Source:** csv
  **Sourcetype:** csv
  **URL:** https://raw.githubusercontent.com/splunk/attack_data/master/datasets/m365_copilot/copilot_prompt_logs.csv


---

*Source: [Splunk Security Content](detections/application/m365_copilot_jailbreak_attempts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
