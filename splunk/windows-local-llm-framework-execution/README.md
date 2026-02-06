# Windows Local LLM Framework Execution

**Type:** Hunting

**Author:** Rod Soto, Splunk

## Description

The following analytic detects execution of unauthorized local LLM frameworks (Ollama, LM Studio, GPT4All, Jan, llama.cpp, KoboldCPP, Oobabooga, NutStudio) and Python-based AI/ML libraries (HuggingFace Transformers, LangChain) on Windows endpoints by leveraging process creation events.
It identifies cases where known LLM framework executables are launched or command-line arguments reference AI/ML libraries.
This activity is significant as it may indicate shadow AI deployments, unauthorized model inference operations, or potential data exfiltration through local AI systems.
If confirmed malicious, this could lead to unauthorized access to sensitive data, intellectual property theft, or circumvention of organizational AI governance policies.


## MITRE ATT&CK

- T1543

## Analytic Stories

- Suspicious Local LLM Frameworks

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/local_llms/sysmon_local_llms.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_local_llm_framework_execution.yml)*
