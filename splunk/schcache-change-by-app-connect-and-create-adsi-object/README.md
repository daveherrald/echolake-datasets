# SchCache Change By App Connect And Create ADSI Object

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects an application attempting to connect and create an ADSI object to perform an LDAP query. It leverages Sysmon EventCode 11 to identify changes in the Active Directory Schema cache files located in %LOCALAPPDATA%\Microsoft\Windows\SchCache or %systemroot%\SchCache. This activity is significant as it can indicate the presence of suspicious applications, such as ransomware, using ADSI object APIs for LDAP queries. If confirmed malicious, this behavior could allow attackers to gather sensitive directory information, potentially leading to further exploitation or lateral movement within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- BlackMatter Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/blackmatter_schcache/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/schcache_change_by_app_connect_and_create_adsi_object.yml)*
