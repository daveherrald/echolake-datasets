# Windows Credentials from Password Stores Chrome LocalState Access

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects non-Chrome processes accessing the Chrome "Local State" file, which contains critical settings and information. It leverages Windows Security Event logs, specifically event code 4663, to identify this behavior. This activity is significant because threat actors can exploit this file to extract the encrypted master key used for decrypting saved passwords in Chrome. If confirmed malicious, this could lead to unauthorized access to sensitive information, posing a severe security risk. Monitoring this anomaly helps identify potential threats and safeguard browser-stored data.

## MITRE ATT&CK

- T1012

## Analytic Stories

- StealC Stealer
- DarkGate Malware
- Malicious Inno Setup Loader
- NjRAT
- Phemedrone Stealer
- Salt Typhoon
- Amadey
- Earth Alux
- Warzone RAT
- Quasar RAT
- PXA Stealer
- RedLine Stealer
- SnappyBee
- Meduza Stealer
- Braodo Stealer
- MoonPeak
- Snake Keylogger
- China-Nexus Threat Activity
- 0bj3ctivity Stealer
- Lokibot
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/chrome_local_state_simulate_access/redline-localstate-smalldata-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_chrome_localstate_access.yml)*
