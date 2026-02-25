# M365 Copilot Non Compliant Devices Accessing M365 Copilot

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects M365 Copilot access from non-compliant or unmanaged devices that violate corporate security policies, indicating potential shadow IT usage, BYOD policy violations, or compromised endpoint access. The detection filters M365 Copilot Graph API events where deviceDetail.isCompliant=false or deviceDetail.isManaged=false, then aggregates by user, operating system, and browser to calculate metrics including event counts, unique IPs and locations, and compliance/management status over time. Users accessing Copilot from non-compliant or unmanaged devices are flagged and sorted by activity volume and geographic spread, enabling security teams to identify unauthorized endpoints that may lack proper security controls, encryption, or MDM enrollment.

## MITRE ATT&CK

- T1562

## Analytic Stories

- Suspicious Microsoft 365 Copilot Activities

## Data Sources

- M365 Copilot Graph API

## Sample Data

- **Source:** AuditLogs.SignIns
  **Sourcetype:** o365:graph:api
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/m365_copilot/m365_copilot_access.log


---

*Source: [Splunk Security Content](detections/application/m365_copilot_non_compliant_devices_accessing_m365_copilot.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
