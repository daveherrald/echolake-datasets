# Powershell Processing Stream Of Data

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious PowerShell script execution involving compressed stream data processing, identified via EventCode 4104. It leverages PowerShell Script Block Logging to flag scripts using `IO.Compression`, `IO.StreamReader`, or decompression methods. This activity is significant as it often indicates obfuscated PowerShell or embedded .NET/binary execution, which are common tactics for evading detection. If confirmed malicious, this behavior could allow attackers to execute hidden code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Hellcat Ransomware
- Malicious PowerShell
- Medusa Ransomware
- PXA Stealer
- Data Destruction
- Braodo Stealer
- AsyncRAT
- Hermetic Wiper
- IcedID
- XWorm
- MoonPeak

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/streamreader.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_processing_stream_of_data.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
