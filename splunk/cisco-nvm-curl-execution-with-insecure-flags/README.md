# Cisco NVM - Curl Execution With Insecure Flags

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects the use of `curl.exe` with insecure flags such as `-k`, `--insecure`, `--proxy-insecure`, or `--doh-insecure`
which disable TLS certificate validation.
It leverages Cisco Network Visibility Module (NVM) flow data and process arguments
to identify outbound connections initiated by curl where TLS checks were explicitly disabled.
This behavior may indicate an attempt to bypass certificate validation to connect to potentially untrusted or malicious endpoints,
a common tactic in red team operations, malware staging, or data exfiltration over HTTPS.


## MITRE ATT&CK

- T1197

## Analytic Stories

- Cisco Network Visibility Module Analytics
- PromptLock
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___curl_execution_with_insecure_flags.yml)*
