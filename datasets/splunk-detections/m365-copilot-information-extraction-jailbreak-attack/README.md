# M365 Copilot Information Extraction Jailbreak Attack

**Type:** TTP

**Author:** Rod Soto

## Description

Detects M365 Copilot information extraction jailbreak attacks that attempt to obtain sensitive, classified, or comprehensive data through various social engineering techniques including fictional entity impersonation, bulk data requests, and privacy bypass attempts. The detection searches exported eDiscovery prompt logs for extraction keywords like "transcendent," "tell me everything," "confidential," "dump," "extract," "reveal," and "bypass" in the Subject_Title field, categorizing each attempt by extraction type and assigning severity levels (CRITICAL for classified/proprietary data, HIGH for bulk extraction or privacy bypass). Prompts are further analyzed for compound risk patterns such as "Confidential+Extraction" or "Bulk_Request+Bypass," filtering out low-severity cases to surface the most dangerous attempts to exfiltrate sensitive organizational information through AI manipulation.

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

*Source: [Splunk Security Content](detections/application/m365_copilot_information_extraction_jailbreak_attack.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
