# MOVEit Empty Key Fingerprint Authentication Attempt

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This detection identifies attempts to authenticate with an empty public key fingerprint in Progress MOVEit Transfer, which is a key indicator of potential exploitation of the CVE-2024-5806 vulnerability. Such attempts are characteristic of the authentication bypass technique used in this vulnerability, where attackers try to impersonate valid users without providing proper credentials. While occasional empty key fingerprint authentication attempts might occur due to misconfigurations, a sudden increase or attempts from unexpected sources could signify malicious activity. This analytic helps security teams identify and investigate potential exploitation attempts of the MOVEit Transfer authentication bypass vulnerability.

## MITRE ATT&CK

- T1190

## Analytic Stories

- MOVEit Transfer Authentication Bypass
- Hellcat Ransomware

## Data Sources


## Sample Data

- **Source:** sftp_server_logs
  **Sourcetype:** sftp_server_logs
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/moveit/SftpServer.log


---

*Source: [Splunk Security Content](detections/endpoint/moveit_empty_key_fingerprint_authentication_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
