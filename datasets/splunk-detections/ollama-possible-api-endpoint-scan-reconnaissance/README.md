# Ollama Possible API Endpoint Scan Reconnaissance

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects API reconnaissance and endpoint scanning activity against Ollama servers by identifying sources probing multiple API endpoints within short timeframes, particularly when using HEAD requests or accessing diverse endpoint paths, which indicates systematic enumeration to map the API surface, discover hidden endpoints, or identify vulnerabilities before launching targeted attacks.

## MITRE ATT&CK

- T1595

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** server.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/server.log


---

*Source: [Splunk Security Content](detections/application/ollama_possible_api_endpoint_scan_reconnaissance.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
