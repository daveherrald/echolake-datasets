# Cisco Isovalent - Non Allowlisted Image Use

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting use of container images that fall outside an approved
allowlist, leveraging Cisco Isovalent/Tetragon runtime telemetry (image name and
workload identity). Adversaries commonly introduce untrusted or newly published
images to deploy tooling, establish persistence, or abuse supply‑chain trust. This
behavior may indicate image pulls from unauthorized registries, execution of
unvetted software, or a drift from established deployment baselines. Extra scrutiny
is warranted for namespaces and workloads that normally source images from restricted
registries, and for pods that suddenly begin running images outside expected
prefixes.
Maintain an environment‑specific allowlist via the macro `cisco_isovalent_allowed_images`
(for example, allow trusted registries/prefixes such as ImageName="gcr.io/org/*",
"registry.local/*", or "myco/*") and keep it updated as new baseline images are
introduced. This analytic alerts on images NOT matching the allowlist.


## MITRE ATT&CK

- T1204.003

## Analytic Stories

- Cisco Isovalent Suspicious Activity

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___non_allowlisted_image_use.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
