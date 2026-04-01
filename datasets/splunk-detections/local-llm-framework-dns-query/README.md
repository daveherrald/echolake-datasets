# Local LLM Framework DNS Query

**Type:** Hunting

**Author:** Rod Soto

## Description

Detects DNS queries related to local LLM models on endpoints by monitoring Sysmon DNS query events (Event ID 22) for known LLM model domains and services.
Local LLM frameworks like Ollama, LM Studio, and GPT4All make DNS calls to repositories such as huggingface.co and ollama.ai for model downloads, updates, and telemetry.
These queries can reveal unauthorized AI tool usage or data exfiltration risks on corporate networks.


## MITRE ATT&CK

- T1590

## Analytic Stories

- Suspicious Local LLM Frameworks

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/local_llms/sysmon_dns.log


---

*Source: [Splunk Security Content](detections/endpoint/local_llm_framework_dns_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
