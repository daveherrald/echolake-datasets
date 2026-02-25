# Detect Empire with PowerShell Script Block Logging

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting suspicious PowerShell execution indicative of PowerShell-Empire activity. It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze commands sent to PowerShell, specifically looking for patterns involving `system.net.webclient` and base64 encoding. This behavior is significant as it often represents initial stagers used by PowerShell-Empire, a known post-exploitation framework. If confirmed malicious, this activity could allow attackers to download and execute additional payloads, leading to potential code execution, data exfiltration, or further compromise of the affected system.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Hellcat Ransomware
- Malicious PowerShell
- Hermetic Wiper
- Data Destruction

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/empire.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_empire_with_powershell_script_block_logging.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
