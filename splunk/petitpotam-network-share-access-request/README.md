# PetitPotam Network Share Access Request

**Type:** TTP

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

The following analytic detects network share access requests indicative of the PetitPotam attack (CVE-2021-36942). It leverages Windows Event Code 5145, which logs attempts to access network share objects. This detection is significant as PetitPotam can coerce authentication from domain controllers, potentially leading to unauthorized access. If confirmed malicious, this activity could allow attackers to escalate privileges or move laterally within the network, posing a severe security risk. Ensure Event Code 5145 is enabled via Group Policy to utilize this analytic effectively.

## MITRE ATT&CK

- T1187

## Analytic Stories

- PetitPotam NTLM Relay on Active Directory Certificate Services

## Data Sources

- Windows Event Log Security 5145

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1187/petitpotam/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/petitpotam_network_share_access_request.yml)*
