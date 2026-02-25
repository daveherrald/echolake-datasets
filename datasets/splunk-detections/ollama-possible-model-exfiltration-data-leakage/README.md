# Ollama Possible Model Exfiltration Data Leakage

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects data leakage and exfiltration attempts targeting Ollama model metadata and configuration endpoints. Adversaries repeatedly query /api/show, /api/tags, and /api/v1/models to systematically extract sensitive model information including architecture details, fine-tuning parameters, system paths, Modelfile configurations, and proprietary customizations. Multiple inspection attempts within a 15-minute window indicate automated exfiltration of valuable intellectual property such as custom model configurations, system prompts, and internal model specifications. This activity represents unauthorized data disclosure that could enable competitive intelligence gathering, model replication, or preparation for advanced attacks against the AI infrastructure.

## MITRE ATT&CK

- T1048

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** server.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/server.log


---

*Source: [Splunk Security Content](detections/application/ollama_possible_model_exfiltration_data_leakage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
