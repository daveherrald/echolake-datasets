# M365 Copilot Agentic Jailbreak Attack

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects agentic AI jailbreak attempts that try to establish persistent control over M365 Copilot through rule injection, universal triggers, response automation, system overrides, and persona establishment techniques. The detection analyzes the PromptText field for keywords like "from now on," "always respond," "ignore previous," "new rule," "override," and role-playing commands (e.g., "act as," "you are now") that attempt to inject persistent instructions. The search computes risk by counting distinct jailbreak indicators per user session, flagging coordinated manipulation attempts.

## MITRE ATT&CK

- T1562

## Analytic Stories

- Suspicious Microsoft 365 Copilot Activities

## Data Sources

- M365 Exported eDiscovery Prompts

## Sample Data

- **Source:** csv
  **Sourcetype:** csv
  **URL:** https://raw.githubusercontent.com/splunk/attack_data/master/datasets/m365_copilot/copilot_prompt_logs.csv


---

*Source: [Splunk Security Content](detections/application/m365_copilot_agentic_jailbreak_attack.yml)*
