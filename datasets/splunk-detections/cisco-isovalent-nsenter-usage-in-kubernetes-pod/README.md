# Cisco Isovalent - Nsenter Usage in Kubernetes Pod

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This analytic detects the execution of the nsenter utility from within a container, a technique often used for exploitation and container escape. Nsenter allows an attacker to enter the namespaces of another process—such as the host's init process (PID 1)—and execute a shell or other binaries with elevated privileges. For example, an attacker may use docker exec to gain a shell in a container, enumerate the PID of a target container or the host, and then use nsenter to access all namespaces (mount, UTS, IPC, net, pid) of the host or another container.  Example to escape to the host: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`. The WorkloadAncestorsBinary field is used to track the ancestry of the process, this is useful to understand the context of the nsenter usage.

The options -m -u -n -i -p correspond to the various Linux namespaces. Adversaries exploit nsenter when pods are misconfigured with excessive privileges (e.g., privileged, hostPID, or broad hostPath mounts), enabling them to interact with the underlying node filesystem and processes. This can be an indicator of a container escape attempt or privilege escalation. Security teams should pay close attention to any nsenter invocation from within containers, especially outside of normal maintenance activity or in workloads with elevated privileges. 


## MITRE ATT&CK

- T1543

## Analytic Stories

- Cisco Isovalent Suspicious Activity

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___nsenter_usage_in_kubernetes_pod.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
