# WS FTP Remote Code Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting potential Remote Code Execution (RCE) attempts exploiting CVE-2023-40044 in WS_FTP software. It identifies HTTP POST requests to the "/AHT/AhtApiService.asmx/AuthUser" URL with a status code of 200. This detection leverages the Web datamodel to monitor specific URL patterns and HTTP status codes. This activity is significant as it may indicate an exploitation attempt, potentially allowing an attacker to execute arbitrary code on the server. If confirmed malicious, this could lead to unauthorized access, data exfiltration, or further compromise of the affected system.

## MITRE ATT&CK

- T1190

## Analytic Stories

- WS FTP Server Critical Vulnerabilities

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/ws_ftp/wsftpweb.log


---

*Source: [Splunk Security Content](detections/web/ws_ftp_remote_code_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
