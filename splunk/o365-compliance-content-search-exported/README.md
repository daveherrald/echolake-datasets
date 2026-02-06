# O365 Compliance Content Search Exported

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies when the results of a content search within the Office 365 Security and Compliance Center are exported. It uses the SearchExported operation from the SecurityComplianceCenter workload in the o365_management_activity data source. This activity is significant because exporting search results can involve sensitive or critical organizational data, potentially leading to data exfiltration. If confirmed malicious, an attacker could gain access to and exfiltrate sensitive information, posing a severe risk to the organization's data security and compliance posture.

## MITRE ATT&CK

- T1114.002

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/o365_compliance_content_search_exported/o365_compliance_content_search_exported.log


---

*Source: [Splunk Security Content](detections/cloud/o365_compliance_content_search_exported.yml)*
