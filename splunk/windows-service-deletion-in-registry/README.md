# Windows Service Deletion In Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of a service from the Windows Registry under CurrentControlSet\Services. It leverages data from the Endpoint.Registry datamodel, specifically monitoring registry paths and actions related to service deletion. This activity is significant as adversaries may delete services to evade detection and hinder incident response efforts. If confirmed malicious, this action could disrupt legitimate services, impair system functionality, and potentially allow attackers to maintain a lower profile within the environment, complicating detection and remediation efforts.

## MITRE ATT&CK

- T1489

## Analytic Stories

- PlugX
- Crypto Stealer
- Brute Ratel C4

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/service_deletion/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_deletion_in_registry.yml)*
