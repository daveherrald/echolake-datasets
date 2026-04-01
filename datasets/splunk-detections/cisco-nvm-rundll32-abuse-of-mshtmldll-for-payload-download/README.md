# Cisco NVM - Rundll32 Abuse of MSHTML.DLL for Payload Download

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects suspicious use of `rundll32.exe` in combination with `mshtml.dll` and the export `RunHTMLApplication`.
This behavior is often observed in malware to execute JavaScript or VBScript in memory, enabling payload staging or
bypassing script execution policies and bypassing the usage of the "mshta.exe" binary.
The detection leverages Cisco Network Visibility Module telemetry which offers network flow activity
along with process information such as command-line arguments
If confirmed malicious, this activity may indicate initial access or payload download.


## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___rundll32_abuse_of_mshtml_dll_for_payload_download.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
