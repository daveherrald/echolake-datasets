# Windows SharePoint Spinstall0 GET Request

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting potential post-exploitation activity related to the Microsoft SharePoint CVE-2025-53770 vulnerability. After successful exploitation via the ToolPane.aspx endpoint, attackers typically deploy a webshell named "spinstall0.aspx" in the SharePoint layouts directory. This detection identifies GET requests to this webshell, which indicates active use of the backdoor for command execution, data exfiltration, or credential/key extraction. Attackers commonly use these webshells to extract encryption keys, authentication tokens, and other sensitive information from the compromised SharePoint server.

## MITRE ATT&CK

- T1190
- T1505.003
- T1552

## Analytic Stories

- Microsoft SharePoint Vulnerabilities

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/sharepoint/spinstall0.log


---

*Source: [Splunk Security Content](detections/web/windows_sharepoint_spinstall0_get_request.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
