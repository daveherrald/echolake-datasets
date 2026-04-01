# Java Class File download by Java User Agent

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying a Java user agent performing a GET request for a .class file from a remote site. It leverages web or proxy logs within the Web Datamodel to detect this activity. This behavior is significant as it may indicate exploitation attempts, such as those related to CVE-2021-44228 (Log4Shell). If confirmed malicious, an attacker could exploit vulnerabilities in the Java application, potentially leading to remote code execution and further compromise of the affected system.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Log4Shell CVE-2021-44228

## Data Sources

- Splunk Stream HTTP

## Sample Data

- **Source:** stream:http
  **Sourcetype:** stream:http
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/java.log


---

*Source: [Splunk Security Content](detections/web/java_class_file_download_by_java_user_agent.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
