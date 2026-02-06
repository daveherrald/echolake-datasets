# Windows AD Object Owner Updated

**Type:** TTP

**Author:** Dean Luxton

## Description

AD Object Owner Updated. The owner provides Full control level privileges over the target AD Object. This event has significant impact alone and is also a precursor activity for hiding an AD object.

## MITRE ATT&CK

- T1222.001
- T1484

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/dacl_abuse/owner_updated_windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_object_owner_updated.yml)*
