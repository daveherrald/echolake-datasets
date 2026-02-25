# Cisco Secure Firewall - Intrusion Events by Threat Activity

**Type:** Anomaly

**Author:** Bhavin Patel, Nasreddine Bencherchali, Splunk

## Description

This analytic detects intrusion events from known threat activity using Cisco Secure Firewall Intrusion Events.
It leverages Cisco Secure Firewall Threat Defense IntrusionEvent logs to identify cases where one or multiple Snort signatures
associated with a known threat or threat actor activity have been triggered within a one-hour time window. The detection uses a
lookup table (cisco_snort_ids_to_threat_mapping) to map Snort signature IDs to known threat actors and their techniques.
When multiple signatures associated with the same threat actor are triggered within the time window, and the count of
unique signatures matches or exceeds the expected number of signatures for that threat technique, an alert is generated.
This helps identify potential coordinated threat activity in your network environment by correlating related intrusion
events that occur in close temporal proximity.

Currently, this detection will alert on the following threat actors or malware families as defined in the cisco_snort_ids_to_threat_mapping lookup:

* AgentTesla
* Amadey
* ArcaneDoor
* AsyncRAT
* CastleRAT
* Chafer
* DCRAT
* LokiBot
* Lumma Stealer
* Nobelium
* Quasar
* Remcos
* Snake
* Static Tundra
* Xworm

To add or update threat actors, update the cisco_snort_ids_to_threat_mapping.csv lookup file with new or modified threat names and associated Snort signature IDs.


## MITRE ATT&CK

- T1041
- T1573.002

## Analytic Stories

- Cisco Secure Firewall Threat Defense Analytics
- ArcaneDoor

## Data Sources

- Cisco Secure Firewall Threat Defense Intrusion Event

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/lumma_stealer/lumma_stealer_events.log


---

*Source: [Splunk Security Content](detections/network/cisco_secure_firewall___intrusion_events_by_threat_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
