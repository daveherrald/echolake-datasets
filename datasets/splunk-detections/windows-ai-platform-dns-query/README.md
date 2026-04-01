# Windows AI Platform DNS Query

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting DNS queries initiated by the Windows AI Platform to domains associated with Hugging Face, OpenAI, and other popular providers of machine learning models and services. Monitoring these DNS requests is important because it can reveal when systems are accessing external AI platforms, which may indicate the use of third-party AI resources or the transfer of sensitive data outside the organization’s environment. Detecting such activity enables organizations to enforce data governance policies, prevent unapproved use of external AI services, and maintain visibility into potential data exfiltration risks. Proactive monitoring provides better control over AI model usage and helps safeguard organizational data flows.


## MITRE ATT&CK

- T1071.004

## Analytic Stories

- LAMEHUG
- SesameOp
- PromptFlux

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1071.004/hugging_face/huggingface.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ai_platform_dns_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
