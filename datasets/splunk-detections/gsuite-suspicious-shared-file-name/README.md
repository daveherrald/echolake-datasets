# Gsuite Suspicious Shared File Name

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting shared files in Google Drive with suspicious filenames commonly used in spear phishing campaigns. It leverages GSuite Drive logs to identify documents with titles that include keywords like "dhl," "ups," "invoice," and "shipment." This activity is significant because such filenames are often used to lure users into opening malicious documents or clicking harmful links. If confirmed malicious, this activity could lead to unauthorized access, data theft, or further compromise of the user's system.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Dev Sec Ops

## Data Sources

- G Suite Drive

## Sample Data

- **Source:** http:gsuite
  **Sourcetype:** gws:reports:drive
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gdrive_susp_file_share/gdrive_susp_attach.log


---

*Source: [Splunk Security Content](detections/cloud/gsuite_suspicious_shared_file_name.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
