# T1047-8: Windows Management Instrumentation — Create a Process using obfuscated Win32_Process

## Technique Context

T1047 Windows Management Instrumentation is a powerful lateral movement and execution technique that leverages Windows' built-in WMI infrastructure to execute commands and processes remotely or locally. Attackers commonly use WMI for process creation through the Win32_Process class, often as a living-off-the-land technique to blend with legitimate administrative activity. This specific test demonstrates an obfuscation variant where attackers create a custom WMI class derived from Win32_Process before executing commands, potentially evading detections focused on standard Win32_Process usage patterns.

The detection community typically focuses on WMI process creation events, unusual WMI class creation/modification, PowerShell interactions with WMI objects, and parent-child process relationships involving WMI Provider Service (WmiPrvSE.exe). This technique is particularly concerning because it provides a native Windows capability for process execution that can bypass application whitelisting and appears as legitimate system activity.

## What This Dataset Contains

This dataset captures a successful WMI-based process execution with class obfuscation. The attack flow shows PowerShell creating a custom WMI class "Win32_Atomic" derived from Win32_Process, then using Invoke-WmiMethod to spawn notepad.exe through this obfuscated class.

Key telemetry includes:
- **PowerShell Script Block 4104**: Complete PowerShell command showing the obfuscation technique: `$Class = New-Object Management.ManagementClass(New-Object Management.ManagementPath("Win32_Process"))`, `$NewClass = $Class.Derive("Win32_Atomic")`, `$NewClass.Put()`, and `Invoke-WmiMethod -Path Win32_Atomic -Name create -ArgumentList notepad.exe`
- **PowerShell Module 4103**: Individual cmdlet invocations for New-Object (ManagementPath and ManagementClass) and Invoke-WmiMethod with the custom Win32_Atomic class
- **Security 4688**: Process creation showing the child PowerShell process with the full obfuscated command line in the Security log
- **Security 4688**: Final notepad.exe creation with WmiPrvSE.exe (PID 4844) as parent, confirming WMI-mediated execution
- **Sysmon 1**: Process creation events for whoami.exe, the PowerShell child process, and notepad.exe with complete parent-child chains
- **Sysmon 7**: WMI-related DLL loading including wmiutils.dll in the PowerShell process at 17:52:25.921
- **Sysmon 10**: Process access events showing PowerShell accessing both whoami.exe and the child PowerShell process with full access rights (0x1FFFFF)

## What This Dataset Does Not Contain

The dataset lacks certain WMI-specific telemetry that would provide deeper visibility into the technique:
- **WMI Activity logs** (Microsoft-Windows-WMI-Activity/Operational) which would show the custom class creation and method invocation
- **Sysmon EID 19-21** (WMI events) are not present, likely due to the sysmon-modular configuration not capturing WMI filtering events
- **Network connections** from WMI operations, though this test was local execution
- **Registry modifications** related to WMI class registration, which may not be captured by the current Sysmon configuration

The parent PowerShell process creation (PID 38048/39048) is not captured in Sysmon EID 1 due to the include-mode filtering, but is available in Security 4688 events.

## Assessment

This dataset provides excellent coverage of WMI-based process execution with obfuscation from multiple complementary log sources. The PowerShell logging captures the complete attack methodology including the class derivation technique, while Security and Sysmon events provide the process execution evidence. The combination of PowerShell script blocks, module logging, and process creation events creates a comprehensive detection opportunity set.

The parent-child process relationship showing notepad.exe spawned by WmiPrvSE.exe is particularly valuable for detection, as this is a strong indicator of WMI-mediated process creation. However, organizations should supplement this with dedicated WMI Activity logging for complete coverage of WMI operations.

## Detection Opportunities Present in This Data

1. **PowerShell WMI class derivation**: Script block 4104 events containing `Management.ManagementClass` operations with `.Derive()` method calls creating custom WMI classes
2. **Custom WMI class creation**: PowerShell invoking `$NewClass.Put()` to register derived WMI classes in the repository
3. **Obfuscated WMI method invocation**: `Invoke-WmiMethod` commands using custom class paths (non-standard class names like "Win32_Atomic")
4. **WMI Provider Service process creation**: Security 4688 or Sysmon 1 events showing processes created by WmiPrvSE.exe as parent
5. **PowerShell WMI DLL loading**: Sysmon 7 events showing wmiutils.dll loading in PowerShell processes
6. **PowerShell module logging correlation**: Security 4103 events showing New-Object Management.ManagementClass and Invoke-WmiMethod cmdlet usage in sequence
7. **Process access patterns**: Sysmon 10 events showing PowerShell processes accessing newly created processes with high privilege levels (0x1FFFFF)
8. **Command-line evidence**: Security 4688 events with full PowerShell command lines containing WMI class manipulation and process creation
