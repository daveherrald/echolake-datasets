# Cisco TFTP Server Configuration for Data Exfiltration

**Type:** TTP

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects the configuration of TFTP services on Cisco IOS devices that could be used to exfiltrate sensitive configuration files. Threat actors like Static Tundra have been observed configuring TFTP servers to make device configuration files accessible for exfiltration after gaining initial access. The detection specifically looks for commands that expose critical configuration files such as startup-config, running-config, and other sensitive system information through TFTP. This activity is particularly concerning as it may represent an attempt to steal credentials, network topology information, and other sensitive data stored in device configurations.

## MITRE ATT&CK

- T1567
- T1005

## Analytic Stories

- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Cisco IOS Logs

## Sample Data

- **Source:** cisco:ios
  **Sourcetype:** cisco:ios
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/cisco_ios.log


---

*Source: [Splunk Security Content](detections/network/cisco_tftp_server_configuration_for_data_exfiltration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
