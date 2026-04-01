# Detect Copy of ShadowCopy with Script Block Logging

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of PowerShell commands to copy the SAM, SYSTEM, or SECURITY hives, which are critical for credential theft. It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze the full command executed. This activity is significant as it indicates an attempt to exfiltrate sensitive registry hives for offline password cracking. If confirmed malicious, this could lead to unauthorized access to credentials, enabling further compromise of the system and potential lateral movement within the network.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Credential Dumping
- VanHelsing Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/detect_copy_of_shadowcopy_with_script_block_logging/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_copy_of_shadowcopy_with_script_block_logging.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
