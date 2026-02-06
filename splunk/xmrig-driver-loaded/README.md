# XMRIG Driver Loaded

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the installation of the XMRIG coinminer driver on a system. It identifies the loading of the `WinRing0x64.sys` driver, commonly associated with XMRIG, by analyzing Sysmon EventCode 6 logs for specific signatures and image loads. This activity is significant because XMRIG is an open-source CPU miner frequently exploited by adversaries to mine cryptocurrency illicitly. If confirmed malicious, this activity could lead to unauthorized resource consumption, degraded system performance, and potential financial loss due to unauthorized cryptocurrency mining.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- CISA AA22-320A
- Crypto Stealer
- XMRig

## Data Sources

- Sysmon EventID 6

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/xmrig_driver_loaded.yml)*
