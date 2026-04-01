# DNS Kerberos Coercion

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

Detects DNS-based Kerberos coercion attacks where adversaries inject marshaled credential structures into DNS records to spoof SPNs and redirect authentication such as in CVE-2025-33073. This detection leverages suricata looking for specific CREDENTIAL_TARGET_INFORMATION structures in DNS queries.

## MITRE ATT&CK

- T1557.001
- T1187
- T1071.004

## Analytic Stories

- Compromised Windows Host
- Suspicious DNS Traffic
- Local Privilege Escalation With KrbRelayUp
- Kerberos Coercion with DNS

## Data Sources

- Suricata
- Sysmon EventID 22

## Sample Data

- **Source:** Suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/kerberos_coercion/suricata.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/kerberos_coercion/sysmon.log


---

*Source: [Splunk Security Content](detections/network/dns_kerberos_coercion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
