# Attempt To Add Certificate To Untrusted Store

**Type:** Anomaly

**Author:** Patrick Bareiss, Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting attempts to add a certificate to the untrusted
certificate store using the 'certutil -addstore' command. 
It leverages process activity and command-line arguments from Endpoint Detection and Response (EDR) logs mapped to the Splunk `Processes` data model. 
This activity is significant as it may indicate an attacker trying to disable security tools to gain unauthorized access.
If confirmed malicious, this could lead to the compromise of system security, allowing attackers
to bypass defenses and potentially escalate privileges or persist in the environment.


## MITRE ATT&CK

- T1553.004

## Analytic Stories

- Disabling Security Tools

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.004/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/attempt_to_add_certificate_to_untrusted_store.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
