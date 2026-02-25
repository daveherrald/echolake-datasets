# Windows Spearphishing Attachment Connect To None MS Office Domain

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying suspicious Office documents that connect to non-Microsoft Office domains. It leverages Sysmon EventCode 22 to detect processes like winword.exe or excel.exe making DNS queries to domains outside of *.office.com or *.office.net. This activity is significant as it may indicate a spearphishing attempt using malicious documents to download or connect to harmful content. If confirmed malicious, this could lead to unauthorized data access, malware infection, or further network compromise.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- AsyncRAT

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/office_doc_abuses_rels/sysmon.log


---

*Source: [Splunk Security Content](detections/network/windows_spearphishing_attachment_connect_to_none_ms_office_domain.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
