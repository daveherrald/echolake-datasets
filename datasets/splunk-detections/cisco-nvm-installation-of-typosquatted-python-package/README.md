# Cisco NVM - Installation of Typosquatted Python Package

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects suspicious python package installations where the package name resembles popular Python libraries but may be typosquatted or slightly altered.
Typosquatting is a common technique used by attackers to trick users into installing malicious packages that mimic legitimate ones.
This detection leverages Cisco NVM flow telemetry and checks for pip or poetry package managers with the "install" or "add" flags, making outbound connections to package repository such as `pypi.org` with known or suspected typo package names.


## MITRE ATT&CK

- T1059

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___installation_of_typosquatted_python_package.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
