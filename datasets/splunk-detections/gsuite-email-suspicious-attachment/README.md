# GSuite Email Suspicious Attachment

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious attachment file extensions in GSuite emails, potentially indicating a spear-phishing attack. It leverages GSuite Gmail logs to identify emails with attachments having file extensions commonly associated with malware, such as .exe, .bat, and .js. This activity is significant as these file types are often used to deliver malicious payloads, posing a risk of compromising targeted machines. If confirmed malicious, this could lead to unauthorized code execution, data breaches, or further network infiltration.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Dev Sec Ops

## Data Sources

- G Suite Gmail

## Sample Data

- **Source:** http:gsuite
  **Sourcetype:** gsuite:gmail:bigquery
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_attachment_ext/gsuite_gmail_file_ext.log


---

*Source: [Splunk Security Content](detections/cloud/gsuite_email_suspicious_attachment.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
