# MacOS plutil

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the usage of the `plutil` command to modify plist files on macOS systems. It leverages osquery to monitor process events, specifically looking for executions of `/usr/bin/plutil`. This activity is significant because adversaries can use `plutil` to alter plist files, potentially adding malicious binaries or command-line arguments that execute upon user logon or system startup. If confirmed malicious, this could allow attackers to achieve persistence, execute arbitrary code, or escalate privileges, posing a significant threat to the system's security.

## MITRE ATT&CK

- T1647

## Analytic Stories

- Living Off The Land

## Data Sources

- osquery

## Sample Data

- **Source:** osquery
  **Sourcetype:** osquery:results
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1647/atomic_red_team/osquery.log


---

*Source: [Splunk Security Content](detections/endpoint/macos_plutil.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
