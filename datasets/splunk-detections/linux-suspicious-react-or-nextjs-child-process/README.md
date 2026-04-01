# Linux Suspicious React or Next.js Child Process

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects Linux processes such as sh, bash, and common Linux LOLBINs being spawned by React or Next.js application servers.
In the context of CVE-2025-55182 / React2Shell / CVE-2025-66478 for Next.js, successful exploitation can lead to arbitrary JavaScript execution on the server, which in turn is commonly used to invoke Node's child_process APIs (for example child_process.execSync) to run OS-level commands.
Public proof-of-concept payloads and observed in-the-wild exploit traffic show patterns where the vulnerable React Server Components handler triggers process.mainModule.require('child_process').execSync() to execute binaries such as ping, curl, or arbitrary shells on the underlying host.
This detection focuses on suspicious child processes where a Next/React server process spawns an uncommon process.
Such activity might be a strong indicator of exploitation of the aforementioned vulnerability.


## MITRE ATT&CK

- T1190
- T1059.004

## Analytic Stories

- React2Shell

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/emerging_threats/react2shell/react2shell_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_suspicious_react_or_next_js_child_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
