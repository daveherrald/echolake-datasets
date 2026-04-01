# Rundll32 DNSQuery

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious `rundll32.exe` process making HTTP connections and performing DNS queries to web domains. It leverages Sysmon EventCode 22 logs to identify these activities. This behavior is significant as it is commonly associated with IcedID malware, where `rundll32.exe` checks internet connectivity and communicates with C&C servers to download configurations and other components. If confirmed malicious, this activity could allow attackers to establish persistence, download additional payloads, and exfiltrate sensitive data, posing a severe threat to the network.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/network/rundll32_dnsquery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
