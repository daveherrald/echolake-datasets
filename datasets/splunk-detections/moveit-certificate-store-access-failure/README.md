# MOVEit Certificate Store Access Failure

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This detection identifies potential exploitation attempts of the CVE-2024-5806 vulnerability in Progress MOVEit Transfer. It looks for log entries indicating failures to access the certificate store, which can occur when an attacker attempts to exploit the authentication bypass vulnerability. This behavior is a key indicator of attempts to impersonate valid users without proper credentials. While certificate store access failures can occur during normal operations, an unusual increase in such events, especially from unexpected sources, may indicate malicious activity.

## MITRE ATT&CK

- T1190

## Analytic Stories

- MOVEit Transfer Authentication Bypass

## Data Sources


## Sample Data

- **Source:** sftp_server_logs
  **Sourcetype:** sftp_server_logs
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/moveit/SftpServer.log


---

*Source: [Splunk Security Content](detections/endpoint/moveit_certificate_store_access_failure.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
