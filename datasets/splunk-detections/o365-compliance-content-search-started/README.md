# O365 Compliance Content Search Started

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting when a content search is initiated within the Office 365 Security and Compliance Center. It leverages the SearchCreated operation from the o365_management_activity logs under the SecurityComplianceCenter workload. This activity is significant as it may indicate an attempt to access sensitive organizational data, including emails and documents. If confirmed malicious, this could lead to unauthorized data access, potential data exfiltration, and compliance violations. Monitoring this behavior helps ensure the integrity and security of organizational data.

## MITRE ATT&CK

- T1114.002

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/o365_compliance_content_search_started/o365_compliance_content_search_started.log


---

*Source: [Splunk Security Content](detections/cloud/o365_compliance_content_search_started.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
