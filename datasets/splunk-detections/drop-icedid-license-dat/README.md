# Drop IcedID License dat

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the dropping of a suspicious file named "license.dat" in %appdata% or %programdata%. This behavior is associated with the IcedID malware, which uses this file to inject its core bot into other processes for banking credential theft. The detection leverages Sysmon EventCode 11 to monitor file creation events in these directories. This activity is significant as it indicates a potential malware infection aiming to steal sensitive banking information. If confirmed malicious, the attacker could gain unauthorized access to financial data, leading to significant financial loss and data breaches.

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- IcedID

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/drop_icedid_license_dat.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
