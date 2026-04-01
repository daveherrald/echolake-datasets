# MS Scripting Process Loading Ldap Module

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of MS scripting processes (wscript.exe or cscript.exe) loading LDAP-related modules (Wldap32.dll, adsldp.dll, adsldpc.dll). It leverages Sysmon EventCode 7 to identify these specific DLL loads. This activity is significant as it may indicate an attempt to query LDAP for host information, a behavior observed in FIN7 implants. If confirmed malicious, this could allow attackers to gather detailed Active Directory information, potentially leading to further exploitation or data exfiltration.

## MITRE ATT&CK

- T1059.007

## Analytic Stories

- FIN7

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_js_2/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ms_scripting_process_loading_ldap_module.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
