# Windows Credentials from Password Stores Chrome Login Data Access

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies non-Chrome processes accessing the Chrome user data file "login data." This file is an SQLite database containing sensitive information, including saved passwords. The detection leverages Windows Security Event logs, specifically event code 4663, to monitor access attempts. This activity is significant as it may indicate attempts by threat actors to extract and decrypt stored passwords, posing a risk to user credentials. If confirmed malicious, attackers could gain unauthorized access to sensitive accounts and escalate their privileges within the environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/chrome_login_data_simulate_access/redline-login-data-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_chrome_login_data_access.yml)*
