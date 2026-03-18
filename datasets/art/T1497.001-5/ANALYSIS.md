# T1497.001-5: Virtualization/Sandbox Evasion — WMI Manufacturer/Model Listing

## Technique Context

T1497.001 (System Checks) encompasses adversary use of system attributes to infer a virtual or sandbox environment. Querying `Win32_ComputerSystem` via WMI for the `Manufacturer` and `Model` fields is one of the most common VM detection techniques: virtual machine hypervisors typically expose their identity through these fields ("QEMU", "VMware, Inc.", "Microsoft Corporation" with model "Virtual Machine", "VirtualBox", etc.). Unlike the thermal zone query in T1497.001-3, this check queries a class that always exists on Windows systems, so the detection method relies on string-matching the returned values rather than observing a WMI error.

This technique is widely used in commodity malware, RATs, and ransomware droppers. Detection teams focus on `Win32_ComputerSystem` queries that immediately branch on manufacturer/model strings, which is a distinct pattern from routine system inventory activity.

## What This Dataset Contains

The technique is executed via an inline PowerShell script captured in Security Event ID 4688, Sysmon Event ID 1, and PowerShell Event ID 4104:

```
powershell.exe & {
  $Manufacturer = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Manufacturer"
  $Model = Get-WmiObject -Class Win32_ComputerSystem | select-object -expandproperty "Model"
  if((($Manufacturer.ToLower() -eq "microsoft corporation") -and ($Model.ToLower().contains("virtual")))
     -or ($Manufacturer.ToLower().contains("vmware"))
     -or ($Model.ToLower() -eq "virtualbox")) {
    write-host "Virtualization environment detected!"
  } else {
    write-host "No virtualization environment detected!"
  }
}
```

The full script, including the enumerated vendor/model strings being checked ("microsoft corporation", "virtual", "vmware", "virtualbox"), is captured in all three channels. The PowerShell 4104 script block logging captures both the wrapped invocation and the raw script body as separate entries. There is no WMI error event in this dataset (unlike T1497.001-3) because `Win32_ComputerSystem` is always available; the query succeeds on any Windows system regardless of virtualization state.

On QEMU/KVM (the environment used), the manufacturer would be reported as "QEMU" — not in the checked list — which means this script would output "No virtualization environment detected!" despite running in a VM. This is an interesting artifact of the test: it demonstrates that not all VM detection scripts correctly enumerate all hypervisor types.

## What This Dataset Does Not Contain

- **No WMI-Activity 5858 error events**: The `Win32_ComputerSystem` query succeeds without errors; there is no WMI operational log evidence of failure.
- **No `wmic.exe` process creation**: As with T1497.001-3, the `Get-WmiObject` call is entirely in-process within PowerShell — no `wmic.exe` child processes are spawned.
- **No follow-on behavior dependent on the check result**: The script outputs a string and exits. In real malware, a positive VM detection would branch into evasion behavior — those artifacts are absent here.
- **WMI-Activity channel not included**: Unlike T1497.001-3, the `wmi.jsonl` file is not part of this dataset (no WMI operational events were generated for a successful query).

## Assessment

This dataset provides clean, unambiguous evidence of WMI-based VM detection via manufacturer and model string inspection. All three instrumentation channels (Sysmon, Security, PowerShell) capture the full technique script. The vendor strings in the script (`vmware`, `virtualbox`, `microsoft corporation`/`virtual`) are high-fidelity detection indicators — legitimate system inventory scripts rarely branch on these specific vendor names. The dataset pairs well with T1497.001-3 to cover both the error-based and value-based VM detection approaches. Its main limitation is that it does not cover QEMU/KVM detection (which this environment would actually trigger), making it incomplete as a VM detection enumeration.

## Detection Opportunities Present in This Data

1. **PowerShell script block (4104) or command line (4688/Sysmon 1) containing `Win32_ComputerSystem` with manufacturer/model string comparisons against hypervisor vendor names** — The presence of `vmware`, `virtualbox`, or `microsoft corporation`/`virtual` in a `Win32_ComputerSystem` query script is a reliable VM detection indicator.
2. **`Get-WmiObject -Class Win32_ComputerSystem` immediately followed by `ToLower()` comparison against virtualization-related strings** — The `.ToLower()` normalization pattern combined with hypervisor vendor checks is characteristic of VM detection code; this pattern is captured in the 4104 script block.
3. **SYSTEM-context PowerShell querying `Win32_ComputerSystem` Manufacturer and Model properties in the same script block** — Legitimate system inventory tools typically do not query manufacturer and model in SYSTEM context via PowerShell with inline conditional branching.
4. **PowerShell Event ID 4103 (module logging) recording `Get-WmiObject` cmdlet invocations targeting `Win32_ComputerSystem`** — Module logging captures the cmdlet name and class parameter, enabling detection without full script block inspection.
5. **Combination of `select-object -expandproperty "Manufacturer"` and `select-object -expandproperty "Model"` in a single PowerShell session** — Querying both manufacturer and model fields from the same WMI class in rapid succession with string comparison is a specific fingerprint of VM detection scripts.
