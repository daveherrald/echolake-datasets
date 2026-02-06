# F5 TMUI Authentication Bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to exploit the CVE-2023-46747 vulnerability, an authentication bypass flaw in F5 BIG-IP's Configuration utility (TMUI). It identifies this activity by monitoring for specific URI paths such as "*/mgmt/tm/auth/user/*" with the PATCH method and a 200 status code. This behavior is significant for a SOC as it indicates potential unauthorized access attempts, leading to remote code execution. If confirmed malicious, an attacker could gain unauthorized access, execute arbitrary code, steal data, disrupt systems, or conduct further malicious activities within the network.

## Analytic Stories

- F5 Authentication Bypass with TMUI

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/f5/f5_tmui.log


---

*Source: [Splunk Security Content](detections/web/f5_tmui_authentication_bypass.yml)*
