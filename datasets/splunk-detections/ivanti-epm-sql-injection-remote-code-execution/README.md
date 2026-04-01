# Ivanti EPM SQL Injection Remote Code Execution

**Type:** TTP

**Author:** Michael Haag

## Description

This detection identifies potential exploitation of a critical SQL injection vulnerability in Ivanti Endpoint Manager (EPM), identified as CVE-2024-29824. The vulnerability, which has a CVSS score of 9.8, allows for remote code execution through the `RecordGoodApp` function in the `PatchBiz.dll` file. An attacker can exploit this vulnerability by manipulating the `goodApp.md5` value in an HTTP POST request to the `/WSStatusEvents/EventHandler.asmx` endpoint, leading to unauthorized command execution on the server. Monitoring for unusual SQL commands and HTTP requests to this endpoint can help identify exploitation attempts. Note that, the detection is focused on the URI path, HTTP method and status code of 200, indicating potential exploitation. To properly identify if this was successful, TLS inspection and additional network traffic analysis is required as the xp_cmdshell comes in via the request body.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Ivanti EPM Vulnerabilities
- GhostRedirector IIS Module and Rungan Backdoor
- Hellcat Ransomware

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ivanti/suricata_ivanti_epm.log


---

*Source: [Splunk Security Content](detections/web/ivanti_epm_sql_injection_remote_code_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
