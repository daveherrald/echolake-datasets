# Windows Cisco Secure Endpoint Stop Immunet Service Via Sfc

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the use of the `sfc.exe` utility, in order to stop the Immunet Protect service. The Sfc.exe utility is part of Cisco Secure Endpoint installation. This detection leverages telemetry from the endpoint, focusing on command-line executions involving the `-k` parameter. This activity is significant as it indicates potential tampering with defensive mechanisms. If confirmed malicious, attackers could partially blind the EDR, enabling further compromise and lateral movement within the network.

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

*Source: [Splunk Security Content](detections/endpoint/windows_cisco_secure_endpoint_stop_immunet_service_via_sfc.yml)*
