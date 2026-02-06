# Windows Cisco Secure Endpoint Uninstall Immunet Service Via Sfc

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the use of the sfc.exe utility with the "-u" parameter, which is part of the Cisco Secure Endpoint installation. The "-u" flag allows the uninstallation of Cisco Secure Endpoint components. This detection leverages endpoint telemetry to monitor command-line executions that include the "-u" parameter. The use of this flag is significant as it could indicate an attempt to disable or remove endpoint protection, potentially leaving the system vulnerable to further exploitation. If identified as malicious, this action may be part of a broader effort to disable security mechanisms and avoid detection.

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

*Source: [Splunk Security Content](detections/endpoint/windows_cisco_secure_endpoint_uninstall_immunet_service_via_sfc.yml)*
