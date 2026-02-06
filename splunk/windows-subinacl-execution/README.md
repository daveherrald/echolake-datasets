# Windows SubInAcl Execution

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

The following analytic detects the execution of the SubInAcl utility. SubInAcl is a legacy Windows Resource Kit tool from the Windows 2003 era, used to manipulate security descriptors of securable objects. It leverages data from Endpoint Detection and Response (EDR) agents, specifically searching for any process execution involving "SubInAcl.exe" binary. This activity can be significant because the utility should be rarely found on modern Windows machines, which mean any execution could potentially be considered suspicious. If confirmed malicious, this could allow an attacker to blind defenses by tampering with EventLog ACLs or modifying the access to a previously denied resource.

## MITRE ATT&CK

- T1222.001

## Analytic Stories

- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/subinacl/subinacl_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_subinacl_execution.yml)*
