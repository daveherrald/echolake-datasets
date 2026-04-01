# Powershell Enable SMB1Protocol Feature

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the enabling of the SMB1 protocol via `powershell.exe`. It leverages PowerShell script block logging (EventCode 4104) to identify the execution of the `Enable-WindowsOptionalFeature` cmdlet with the `SMB1Protocol` parameter. This activity is significant because enabling SMB1 can facilitate lateral movement and file encryption by ransomware, such as RedDot. If confirmed malicious, this action could allow an attacker to propagate through the network, encrypt files, and potentially disrupt business operations.

## MITRE ATT&CK

- T1027.005

## Analytic Stories

- Ransomware
- Malicious PowerShell
- Hermetic Wiper
- Data Destruction

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_enable_smb1protocol_feature.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
