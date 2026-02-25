# Tomcat Session File Upload Attempt

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection identifies potential exploitation of CVE-2025-24813 in Apache Tomcat through the initial stage of the attack. This first phase occurs when an attacker attempts to upload a malicious serialized Java object with a .session file extension via an HTTP PUT request. When successful, these uploads typically result in HTTP status codes 201 (Created) or 409 (Conflict) and create the foundation for subsequent deserialization attacks by placing malicious content in a location where Tomcat's session management can access it.

## MITRE ATT&CK

- T1190
- T1505.003

## Analytic Stories

- Apache Tomcat Session Deserialization Attacks

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/tomcat/tomcat_nginx_access.log


---

*Source: [Splunk Security Content](detections/web/tomcat_session_file_upload_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
