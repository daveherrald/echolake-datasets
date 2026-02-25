# Windows Security And Backup Services Stop

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the suspicious termination of known services commonly targeted by ransomware before file encryption. It leverages Windows System Event Logs (EventCode 7036) to identify when critical services such as Volume Shadow Copy, backup, and antivirus services are stopped. This activity is significant because ransomware often disables these services to avoid errors and ensure successful file encryption. If confirmed malicious, this behavior could lead to widespread data encryption, rendering files inaccessible and potentially causing significant operational disruption and data loss.

## MITRE ATT&CK

- T1490

## Analytic Stories

- LockBit Ransomware
- Ransomware
- Compromised Windows Host
- BlackMatter Ransomware
- Termite Ransomware
- Scattered Lapsus$ Hunters
- Hellcat Ransomware

## Data Sources

- Windows Event Log System 7036

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/known_services_killed_by_ransomware/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_security_and_backup_services_stop.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
