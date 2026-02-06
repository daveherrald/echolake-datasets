# LLM Model File Creation

**Type:** Hunting

**Author:** Rod Soto

## Description

Detects the creation of Large Language Model (LLM) files on Windows endpoints by monitoring file creation events for specific model file formats and extensions commonly used by local AI frameworks.
This detection identifies potential shadow AI deployments, unauthorized model downloads, and rogue LLM infrastructure by detecting file creation patterns associated with quantized models (.gguf, .ggml), safetensors model format files, and Ollama Modelfiles.
These file types are characteristic of local inference frameworks such as Ollama, llama.cpp, GPT4All, LM Studio, and similar tools that enable running LLMs locally without cloud dependencies.
Organizations can use this detection to identify potential data exfiltration risks, policy violations related to unapproved AI usage, and security blind spots created by decentralized AI deployments that bypass enterprise governance and monitoring.


## MITRE ATT&CK

- T1543

## Analytic Stories

- Suspicious Local LLM Frameworks

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/local_llms/sysmon_local_llms.log


---

*Source: [Splunk Security Content](detections/endpoint/llm_model_file_creation.yml)*
