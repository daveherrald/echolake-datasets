# Microsoft SharePoint Server Elevation of Privilege

**Type:** TTP

**Author:** Michael Haag, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting potential exploitation attempts against Microsoft SharePoint Server vulnerability CVE-2023-29357. It leverages the Web datamodel to monitor for specific API calls and HTTP methods indicative of privilege escalation attempts. This activity is significant as it may indicate an attacker is trying to gain unauthorized privileged access to the SharePoint environment. If confirmed malicious, the impact could include unauthorized access to sensitive data, potential data theft, and further compromise of the SharePoint server, leading to a broader security breach.

## MITRE ATT&CK

- T1068

## Analytic Stories

- Microsoft SharePoint Server Elevation of Privilege CVE-2023-29357

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/sharepoint/sharepointeop.log


---

*Source: [Splunk Security Content](detections/web/microsoft_sharepoint_server_elevation_of_privilege.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
