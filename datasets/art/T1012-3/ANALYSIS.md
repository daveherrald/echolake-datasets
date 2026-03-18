# T1012-3: Query Registry — Enumerate COM Objects in Registry with Powershell

## Technique Context

T1012 (Query Registry) is a Discovery technique where adversaries query the Windows Registry to gather information about system configurations, installed software, security settings, and other system details. This specific test (T1012-3) focuses on enumerating Component Object Model (COM) objects by querying the `HKEY_CLASSES_ROOT\CLSID` registry hive using PowerShell. COM objects are a fundamental part of Windows architecture, and their enumeration can reveal valuable information about available system functionality, installed applications, and potential attack vectors. Adversaries often use this technique for situational awareness and to identify potential tools or capabilities they can leverage for further compromise.

## What This Dataset Contains

This dataset captures PowerShell-based COM object enumeration with extensive telemetry across multiple channels. The core technique is visible in Security event 4688 showing the PowerShell command line: `"powershell.exe" & {New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR; Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > $env:temp\clsids.txt; ForEach($CLSID in Get-Content "$env:temp\clsids.txt"){...}}`.

PowerShell events 4103/4104 provide detailed execution traces showing:
- Registry drive mounting: `New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR`
- CLSID enumeration and file creation: `Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > $env:temp\clsids.txt`
- Individual COM object instantiation attempts: `$handle=[activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))`
- Method enumeration: `$handle | get-member -erroraction silentlycontinue | out-file $env:temp\T1592.002Test1.txt -append`

Specific CLSIDs being processed include `{0000002F-0000-0000-C000-000000000046}`, `{00000300-0000-0000-C000-000000000046}`, and others, with successful COM object instantiations creating `System.__ComObject` instances.

Sysmon captures process creation (EID 1) for the PowerShell execution with PID 1468, file creation events (EID 11) for `C:\Windows\Temp\clsids.txt` and `C:\Windows\Temp\T1592.002Test1.txt`, and extensive DLL loading events (EID 7) including PowerShell automation libraries, .NET runtime components, and Windows Defender integration.

The technique triggers COM object instantiation, leading to process creation for various COM servers including Internet Explorer (`iexplore.exe`, `ielowutil.exe`) with CLSID parameters in their command lines, such as `"C:\Program Files (x86)\Internet Explorer\ielowutil.exe" -CLSID:{0002DF01-0000-0000-C000-000000000046} -Embedding`.

## What This Dataset Does Not Contain

The dataset lacks direct registry access events (no Security 4657 or Sysmon 13 for registry reads), as the Sysmon configuration appears focused on registry value changes rather than reads. Some COM object instantiation attempts may have failed silently due to Windows Defender's active protection, though this didn't prevent the core enumeration from completing successfully. The dataset shows only a subset of COM object processing due to the script's error handling (`try/catch` blocks), so failed instantiations don't generate telemetry. Network connections from COM object instantiation aren't captured, suggesting either no network-enabled objects were processed or network monitoring wasn't configured.

## Assessment

This dataset provides excellent coverage of PowerShell-based registry enumeration techniques. The combination of Security 4688 command-line logging, PowerShell 4103/4104 detailed execution traces, and Sysmon process/file creation events creates a comprehensive detection surface. The PowerShell logs are particularly valuable, showing not just the high-level command but the actual parameter binding and CLSID values being processed. The cascading COM object instantiation creating legitimate processes like Internet Explorer demonstrates how this discovery technique can trigger secondary system activity. However, the lack of direct registry read events limits visibility into which specific registry keys were accessed beyond what's visible in the PowerShell command structure.

## Detection Opportunities Present in This Data

1. **PowerShell Registry Drive Creation**: Monitor PowerShell 4103 events for `New-PSDrive` commands with `-PSProvider registry` and `-Root HKEY_CLASSES_ROOT` parameters indicating CLSID enumeration attempts.

2. **CLSID Enumeration Commands**: Detect PowerShell command lines containing `Get-ChildItem -Path HKCR:\CLSID` or similar registry enumeration patterns targeting the COM object registry hive.

3. **COM Object Instantiation Patterns**: Alert on PowerShell 4103 events showing `[activator]::CreateInstance([type]::GetTypeFromCLSID())` indicating programmatic COM object creation for discovery purposes.

4. **File Creation in Temp Directories**: Monitor Sysmon EID 11 for file creation events with names like `clsids.txt` or patterns suggesting CLSID enumeration output in temporary directories.

5. **Bulk COM Server Process Creation**: Detect unusual process creation patterns where multiple COM servers (iexplore.exe, ielowutil.exe, etc.) are spawned with `-CLSID:{}` or `-Embedding` parameters in short succession.

6. **PowerShell Script Block Analysis**: Analyze PowerShell 4104 events for script blocks containing `GetTypeFromCLSID`, `get-member`, and registry enumeration functions combined with file output operations.

7. **Cross-Process Registry Access**: Correlate PowerShell execution with process creation events for known COM servers to identify when registry enumeration triggers system component activation.

8. **Registry Provider Mount Detection**: Monitor for PowerShell mounting registry hives as drives, particularly HKEY_CLASSES_ROOT, which is uncommon in legitimate administrative scripts.
