# Windows Unusual Intelliform Storage Registry Access

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes accessing Intelliform Storage Registry keys used by Internet Explorer. It leverages Windows Security Event logs, specifically monitoring EventCode 4663, which tracks object access events. This activity is significant because it can indicate unauthorized access or manipulation of sensitive registry keys used for storing form data in Internet Explorer. If confirmed malicious, this could lead to data exfiltration, credential theft, or further compromise of the system.

## MITRE ATT&CK

- T1552.001

## Analytic Stories

- Quasar RAT
- Lokibot

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/ie_intelliform_storage/storage2_sim.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_intelliform_storage_registry_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
