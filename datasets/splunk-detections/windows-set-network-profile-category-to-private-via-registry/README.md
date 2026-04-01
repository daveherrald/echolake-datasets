# Windows Set Network Profile Category to Private via Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting attempts to modify the Windows Registry to change a network profile's category to "Private", which may indicate an adversary is preparing the environment for lateral movement or reducing firewall restrictions. Specifically, this activity involves changes to the Category value within the HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID} registry path. A value of 1 corresponds to a private network profile, which typically enables less restrictive firewall policies. While this action can occur during legitimate network configuration, it may also be a sign of malicious behavior when combined with other indicators such as suspicious account activity, unexpected administrative privilege usage, or execution of unsigned binaries. Monitoring for this registry modification—especially outside standard IT processes or correlated with persistence mechanisms—can help identify stealthy post-exploitation activity.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Secret Blizzard

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/reg_profiles_private2/reg_profiles_private2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_set_network_profile_category_to_private_via_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
