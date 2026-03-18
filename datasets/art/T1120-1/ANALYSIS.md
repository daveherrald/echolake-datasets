# T1120-1: Peripheral Device Discovery — Win32_PnPEntity Hardware Inventory

## Technique Context

T1120 Peripheral Device Discovery enables adversaries to gather information about connected peripheral devices to understand the target environment and identify potential avenues for further exploitation. Attackers commonly use this technique during reconnaissance phases to enumerate hardware components like USB devices, network adapters, storage devices, and other peripherals that might provide attack vectors or contain sensitive data. The Win32_PnPEntity WMI class is particularly valuable as it provides comprehensive information about all Plug and Play devices, including device names, descriptions, manufacturers, and hardware IDs. Detection engineers focus on monitoring WMI queries against device-related classes, PowerShell usage of Get-WMIObject cmdlets, and file operations that store hardware inventory data.

## What This Dataset Contains

The dataset captures a complete execution of peripheral device discovery using PowerShell's Get-WMIObject cmdlet against the Win32_PnPEntity WMI class. Security event 4688 shows the PowerShell process creation with the full command line: `"powershell.exe" & {Get-WMIObject Win32_PnPEntity | Format-Table Name, Description, Manufacturer > $env:TEMP\T1120_collection.txt`. Sysmon event 1 captures the same process creation with process ID 32256 and the complete command line showing WMI enumeration, formatting, and file output redirection. The PowerShell channel (events 4103/4104) reveals detailed cmdlet invocations including `Get-WMIObject`, `Out-File`, `Get-Content`, `Sort-Object`, and `Set-Content` operations. Sysmon event 7 shows WMI-related DLL loading (`wmiutils.dll`) during WMI operations. File creation events (Sysmon 11) document the creation of `C:\Windows\Temp\T1120_collection.txt` containing the device inventory output. The PowerShell command invocation logs show extensive parameter binding for the `Sort-Object` cmdlet, revealing detailed device information including USB controllers, network adapters, storage devices, and virtualization components from the QEMU environment.

## What This Dataset Does Not Contain

The dataset lacks WMI provider logs that would show the actual WMI queries being executed against the Win32_PnPEntity class. Process creation events for `wmiprvse.exe` (WMI Provider Service) are not captured, likely filtered by the sysmon-modular configuration's include-mode ProcessCreate rules. The final contents of the T1120_collection.txt file are not directly visible, though device information is partially captured in PowerShell parameter bindings. Network-based WMI activity is not present since this is local WMI enumeration. Registry access events related to device enumeration from the Windows device manager are not captured as object access auditing is disabled.

## Assessment

This dataset provides excellent telemetry for detecting Win32_PnPEntity-based peripheral device discovery. The combination of Security 4688 command-line logging, Sysmon process creation, and comprehensive PowerShell script block/module logging creates multiple detection opportunities. The WMI DLL loading events add valuable context about WMI usage. However, the absence of WMI provider logs and wmiprvse.exe process events limits visibility into the underlying WMI infrastructure activity. The PowerShell telemetry quality is exceptional, capturing not just the commands but also detailed parameter bindings that reveal the enumerated device data.

## Detection Opportunities Present in This Data

1. PowerShell command line containing "Get-WMIObject Win32_PnPEntity" in Security 4688 or Sysmon 1 events
2. PowerShell script block logging (4104) showing Get-WMIObject cmdlet usage with Win32_PnPEntity class
3. PowerShell module logging (4103) showing Get-WMIObject command invocations with WMI class parameters
4. File creation events (Sysmon 11) for files in temp directories with hardware inventory-related names (T1120_collection.txt)
5. WMI-related DLL loading (wmiutils.dll) in PowerShell processes via Sysmon 7 events
6. PowerShell processes with command lines containing Format-Table operations on device-related properties (Name, Description, Manufacturer)
7. Rapid sequence of PowerShell cmdlet invocations including Get-WMIObject, Format-Table, and file redirection operations
8. PowerShell Sort-Object parameter bindings containing device manufacturer names (Intel, Microsoft, Red Hat) indicating hardware enumeration
9. PowerShell execution with output redirection to environment variable paths ($env:TEMP) for data collection
10. File operations creating text files in system temp directories followed immediately by Get-Content and Set-Content operations on the same files
