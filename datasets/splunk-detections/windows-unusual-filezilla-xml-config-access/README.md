# Windows Unusual FileZilla XML Config Access

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes accessing FileZilla XML config files such as recentservers.xml and sitemanager.xml. It leverages Windows Security Event logs, specifically monitoring EventCode 4663, which tracks object access events. This activity is significant because it can indicate unauthorized access or manipulation of sensitive configuration files used by FileZilla, a popular FTP client. If confirmed malicious, this could lead to data exfiltration, credential theft, or further compromise of the system.

## MITRE ATT&CK

- T1552.001

## Analytic Stories

- Quasar RAT

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/file_xml_config/filezilla_obj.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_filezilla_xml_config_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
