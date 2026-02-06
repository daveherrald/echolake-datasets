# M365 Copilot Impersonation Jailbreak Attack

**Type:** TTP

**Author:** Rod Soto

## Description

Detects M365 Copilot impersonation and roleplay jailbreak attempts where users try to manipulate the AI into adopting alternate personas, behaving as unrestricted entities, or impersonating malicious AI systems to bypass safety controls. The detection searches exported eDiscovery prompt logs for roleplay keywords like "pretend you are," "act as," "you are now," "amoral," and "roleplay as" in the Subject_Title field. Prompts are categorized into specific impersonation types (AI_Impersonation, Malicious_AI_Persona, Unrestricted_AI_Persona, etc.) to identify attempts to override the AI's safety guardrails through persona injection attacks.

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

*Source: [Splunk Security Content](detections/application/m365_copilot_impersonation_jailbreak_attack.yml)*
