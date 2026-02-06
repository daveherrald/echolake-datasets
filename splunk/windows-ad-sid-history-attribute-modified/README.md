# Windows AD SID History Attribute Modified

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects modifications to the SID History attribute in Active Directory by leveraging event code 5136. This detection uses logs from the `wineventlog_security` data source to identify changes to the sIDHistory attribute. Monitoring this activity is crucial as the SID History attribute can be exploited by adversaries to inherit permissions from other accounts, potentially granting unauthorized access. If confirmed malicious, this activity could allow attackers to maintain persistent access and escalate privileges within the domain, posing a significant security risk.

## MITRE ATT&CK

- T1134.005

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134.005/sid_history2/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_sid_history_attribute_modified.yml)*
