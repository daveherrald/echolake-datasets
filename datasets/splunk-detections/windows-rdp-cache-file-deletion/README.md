# Windows RDP Cache File Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the deletion of RDP bitmap cache files—specifically .bmc and .bin files—typically stored in the user profile under the Terminal Server Client\Cache directory. These files are created by the native Windows Remote Desktop Client (mstsc.exe) and store graphical elements from remote sessions to improve performance. Deleting these files may indicate an attempt to remove forensic evidence of RDP usage. While rare in legitimate user behavior, this action is commonly associated with defense evasion techniques used by attackers or red teamers who wish to hide traces of interactive remote access. When observed in conjunction with recent logon activity, RDP session indicators, or script execution, this behavior should be treated as potentially malicious. Monitoring for deletion of these files provides valuable visibility into anti-forensic actions that often follow lateral movement or hands-on-keyboard activity.

## MITRE ATT&CK

- T1070.004

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 23
- Sysmon EventID 26

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.004/bmc_file_deleted/bmc_file_deleted.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_cache_file_deletion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
