# Powershell Using memory As Backing Store

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious PowerShell script execution using memory streams as a backing store, identified via EventCode 4104. It leverages PowerShell Script Block Logging to capture scripts that create new objects with memory streams, often used to decompress and execute payloads in memory. This activity is significant as it indicates potential in-memory execution of malicious code, bypassing traditional file-based detection. If confirmed malicious, this technique could allow attackers to execute arbitrary code, maintain persistence, or escalate privileges without leaving a trace on the disk.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Data Destruction
- MoonPeak
- Medusa Ransomware
- Hermetic Wiper
- IcedID
- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_using_memory_as_backing_store.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
