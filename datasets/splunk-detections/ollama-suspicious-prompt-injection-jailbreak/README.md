# Ollama Suspicious Prompt Injection Jailbreak

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects potential prompt injection or jailbreak attempts against Ollama API endpoints by identifying requests with abnormally long response times. Attackers often craft complex, layered prompts designed to bypass AI safety controls, which typically result in extended processing times as the model attempts to parse and respond to these malicious inputs. This detection monitors /api/generate and /api/chat endpoints for requests exceeding 30 seconds, which may indicate sophisticated jailbreak techniques, multi-stage prompt injections, or attempts to extract sensitive information from the model.

## MITRE ATT&CK

- T1190
- T1059

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** server.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/server.log


---

*Source: [Splunk Security Content](detections/application/ollama_suspicious_prompt_injection_jailbreak.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
