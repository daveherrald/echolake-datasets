# Windows Cisco Secure Endpoint Unblock File Via Sfc

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the use of the sfc.exe utility with the "-unblock" parameter, a feature within Cisco Secure Endpoint. The "-unblock" flag is used to remove system blocks imposed by the endpoint protection. This detection focuses on command-line activity that includes the "-unblock" parameter, as it may indicate an attempt to restore access to files or processes previously blocked by the security software. While this action could be legitimate in troubleshooting scenarios, malicious actors might use it to override protective measures, enabling execution of blocked malicious payloads or bypassing other security mechanisms.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Security Solution Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/cisco_secure_endpoint_tampering/sfc_tampering.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_cisco_secure_endpoint_unblock_file_via_sfc.yml)*
