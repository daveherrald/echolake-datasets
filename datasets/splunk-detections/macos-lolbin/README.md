# MacOS LOLbin

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting multiple executions of Living off the Land (LOLbin) binaries on macOS within a short period. It leverages osquery to monitor process events and identifies commands such as "find", "crontab", "screencapture", "openssl", "curl", "wget", "killall", and "funzip". This activity is significant as LOLbins are often used by attackers to perform malicious actions while evading detection. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or persist within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1059.004

## Analytic Stories

- Living Off The Land
- Hellcat Ransomware

## Data Sources

- osquery

## Sample Data

- **Source:** osquery
  **Sourcetype:** osquery:results
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/macos_lolbin/osquery.log


---

*Source: [Splunk Security Content](detections/endpoint/macos_lolbin.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
