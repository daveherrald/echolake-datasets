# Windows File Without Extension In Critical Folder

**Type:** TTP

**Author:** Teoderick Contreras, Bhavin Patel, Splunk

## Description

This analytic detects the creation of files without extensions in critical Windows system and driver-related directories, including but not limited to System32\Drivers, Windows\WinSxS, and other known Windows driver storage and loading paths. The detection has been expanded to comprehensively cover all commonly abused and legitimate Windows driver folder locations, increasing visibility into attempts to stage or deploy kernel-mode components. The analytic leverages telemetry from the Endpoint.Filesystem data model, with a focus on file creation events and file path analysis. File creation activity in these directories—particularly involving extensionless files—is highly suspicious, as it may indicate the presence of destructive or stealthy malware. This behavior is consistent with malware families such as HermeticWiper, which deploy kernel driver components into trusted Windows driver directories to obtain low-level access and execute destructive payloads. If confirmed malicious, this activity can result in severe system compromise, including the deployment of malicious drivers, boot-sector or filesystem destruction, and ultimately system inoperability and irreversible data loss.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Data Destruction
- Hermetic Wiper

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_without_extension_in_critical_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
