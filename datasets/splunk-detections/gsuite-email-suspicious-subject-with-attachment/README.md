# Gsuite Email Suspicious Subject With Attachment

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying Gsuite emails with suspicious subjects and attachments commonly used in spear phishing attacks. It leverages Gsuite email logs, focusing on specific keywords in the subject line and known malicious file types in attachments. This activity is significant for a SOC as spear phishing is a prevalent method for initial compromise, often leading to further malicious actions. If confirmed malicious, this activity could result in unauthorized access, data exfiltration, or further malware deployment, posing a significant risk to the organization's security.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Dev Sec Ops

## Data Sources

- G Suite Gmail

## Sample Data

- **Source:** http:gsuite
  **Sourcetype:** gsuite:gmail:bigquery
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_subj/gsuite_susp_subj_attach.log


---

*Source: [Splunk Security Content](detections/cloud/gsuite_email_suspicious_subject_with_attachment.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
