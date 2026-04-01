# Windows Driver Inventory

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying drivers being loaded across the fleet. It leverages a PowerShell script input deployed to critical systems to capture driver data. This detection is significant as it helps monitor for unauthorized or malicious drivers that could compromise system integrity. If confirmed malicious, such drivers could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1068

## Analytic Stories

- Windows Drivers

## Data Sources


## Sample Data

- **Source:** PwSh:DriverInventory
  **Sourcetype:** PwSh:DriverInventory
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/driver_inventory.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_driver_inventory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
