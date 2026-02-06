# MacOS LOLbin

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects multiple executions of Living off the Land (LOLbin) binaries on macOS within a short period. It leverages osquery to monitor process events and identifies commands such as "find", "crontab", "screencapture", "openssl", "curl", "wget", "killall", and "funzip". This activity is significant as LOLbins are often used by attackers to perform malicious actions while evading detection. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or persist within the environment, posing a significant security risk.

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
