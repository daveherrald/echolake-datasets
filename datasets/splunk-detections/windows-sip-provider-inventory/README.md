# Windows SIP Provider Inventory

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying all SIP (Subject Interface Package) providers on a Windows system using PowerShell scripted inputs. It detects SIP providers by capturing DLL paths from relevant events. This activity is significant because malicious SIP providers can be used to bypass trust controls, potentially allowing unauthorized code execution. If confirmed malicious, this activity could enable attackers to subvert system integrity, leading to unauthorized access or persistent threats within the environment. Analysts should review for new and non-standard paths to identify potential threats.

## MITRE ATT&CK

- T1553.003

## Analytic Stories

- Subvert Trust Controls SIP and Trust Provider Hijacking

## Data Sources


## Sample Data

- **Source:** powershell://SubjectInterfacePackage
  **Sourcetype:** PwSh:SubjectInterfacePackage
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.003/sip/sip_inventory.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sip_provider_inventory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
