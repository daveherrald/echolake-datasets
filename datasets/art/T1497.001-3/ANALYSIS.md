# T1497.001-3: Virtualization/Sandbox Evasion — System Checks (Thermal Zone WMI Query)

## Technique Context

T1497.001 (System Checks) covers techniques used by malware and adversaries to detect whether they are running inside a virtual machine, sandbox, or analysis environment. If virtualization is detected, the malware may alter behavior, suppress malicious activity, or terminate to avoid analysis. Virtualization detection via WMI is a well-established anti-analysis technique: virtual machines typically do not expose thermal sensors, so querying `MSAcpi_ThermalZoneTemperature` and checking for an error response is a reliable way to infer a VM environment without querying obviously suspicious indicators like manufacturer strings or MAC addresses.

This technique is relevant to the detection community primarily because it appears as a discovery step in multi-stage malware. Detecting it at the WMI query level or at the PowerShell execution level allows defenders to identify sandboxing-aware malware or adversaries performing environment fingerprinting before committing to a more visible attack phase.

## What This Dataset Contains

The technique uses a single PowerShell script captured in Security Event ID 4688 and Sysmon Event ID 1:

```
powershell.exe & {
  $error.clear()
  Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
  if($error) { echo "Virtualization Environment detected" }
}
```

Sysmon Event ID 1 and Security 4688 both capture this script in full as the process command line. The WMI execution failure is recorded in the dataset's `wmi.jsonl` file as a **WMI-Activity/Operational Event ID 5858**:

```
Operation = Start IWbemServices::ExecQuery - root\cimv2 : SELECT * FROM MSAcpi_ThermalZoneTemperature
ResultCode = 0x80041010
```

Result code `0x80041010` (`WBEM_E_INVALID_CLASS`) confirms that the class does not exist in this environment — which is expected on a QEMU/KVM virtual machine where thermal zone WMI classes are not emulated. The WMI error event records the client process ID (12212) and machine name (ACME-WS02), linking it back to the PowerShell process. The PowerShell channel captures the full script block in Event ID 4104.

## What This Dataset Does Not Contain

- **No follow-on behavior**: This test only checks for virtualization and prints a result string. It does not suppress any subsequent activity or branch into a different code path based on the result. Real malware using this check would have observable behavioral differences; those are not present here.
- **No WMI namespace query for the class list**: Sophisticated VM detection scripts sometimes query the WMI namespace for available classes before attempting the thermal query. That is not present in this test.
- **No process creation for `wmic.exe` or `wmiprvse.exe`**: The `Get-WmiObject` call is handled entirely within the PowerShell process via the WMI API. There is no `wmic.exe` child process creation — the WMI query is in-process.
- **WMI-Activity Event ID 5858 is the only WMI channel event**: There is no Event ID 5857 (provider load) or 5861, indicating the query failure was clean and immediate.

## Assessment

This dataset is compact and focused. The most distinctive artifact is the WMI-Activity 5858 event recording the `MSAcpi_ThermalZoneTemperature` query failure — this specific WMI class query is a well-known VM detection indicator and the 5858 event provides direct evidence of the attempt at the WMI layer rather than just at the process layer. Combined with the full PowerShell command line visible in Security 4688 and the 4104 script block, there are three independent evidence sources. The dataset would benefit from additional coverage of the WMI provider host activity and broader anti-VM technique variants. It is best used in combination with T1497.001-5 (which covers the Win32_ComputerSystem manufacturer check) to build comprehensive virtualization-detection rules.

## Detection Opportunities Present in This Data

1. **WMI-Activity Event ID 5858 with `SELECT * FROM MSAcpi_ThermalZoneTemperature`** — The failed WMI query for the thermal zone class is directly observable in the WMI operational log; result code `0x80041010` confirms the class does not exist and the check succeeded in identifying a VM.
2. **PowerShell script block (4104) or command line (4688/Sysmon 1) containing `MSAcpi_ThermalZoneTemperature`** — This specific WMI class name has no legitimate use outside of thermal monitoring software; its appearance in a PowerShell script block is a reliable indicator of VM detection activity.
3. **`Get-WmiObject` query paired with `$error` inspection for virtualization inference** — The pattern of clearing `$error`, running a WMI query with `-ErrorAction SilentlyContinue`, then checking `if($error)` is a standard scripted VM detection idiom.
4. **SYSTEM-context PowerShell querying hardware/sensor WMI namespaces** — Thermal zone and other hardware-specific WMI queries issued by non-interactive, SYSTEM-context PowerShell are unusual outside of hardware monitoring agents.
5. **WMI-Activity 5858 events for hardware or non-standard WMI classes** — Monitoring for WMI query failures against classes not present on standard workloads (thermal zones, BIOS metadata, virtualization-specific namespaces) can surface anti-analysis activity across multiple VM detection techniques.
