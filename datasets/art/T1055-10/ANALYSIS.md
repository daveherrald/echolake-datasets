# T1055-10: Process Injection — Remote Process Injection with Go using CreateRemoteThread WinAPI (Natively)

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where adversaries inject code into legitimate processes to evade detection and execute malicious functionality. This specific test implements remote process injection using the CreateRemoteThread WinAPI call, compiled natively in Go. The technique creates a target process (WerFault.exe) and injects code into it, allowing execution within the context of the legitimate Windows Error Reporting process. Detection engineers typically focus on process access events with high-privilege access rights, cross-process thread creation, and unusual memory allocations or modifications in target processes.

## What This Dataset Contains

The dataset captures a successful process injection attempt with rich telemetry. Security 4688 events show the complete process chain: the initial PowerShell test framework (PID 12044) spawns a child PowerShell process (PID 13124) that executes the injection command `"powershell.exe" & {$process = Start-Process C:\Windows\System32\werfault.exe -passthru; C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThreadNative.exe -pid $process.Id -debug}`. The child PowerShell then launches WerFault.exe (PID 13292) as the injection target.

Critically, Sysmon Event ID 10 captures two process access events showing PowerShell (PID 12044) accessing both whoami.exe (PID 13024) and the child PowerShell process (PID 13124) with full access rights (GrantedAccess: 0x1FFFFF). The CallTrace fields reveal the injection occurring through .NET Framework assemblies: `C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\e742dd873d3be63d30e85f1639febe4d\System.Management.Automation.ni.dll`.

PowerShell script block logging (Event ID 4104) captures the actual injection commands: `{$process = Start-Process C:\Windows\System32\werfault.exe -passthru; C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateRemoteThreadNative.exe -pid $process.Id -debug}`, providing the exact technique implementation.

## What This Dataset Does Not Contain

The dataset is missing the actual CreateRemoteThreadNative.exe execution. The Sysmon ProcessCreate events don't capture this binary launching, likely because it doesn't match the sysmon-modular include-mode filtering patterns. This is a significant gap since the native Go injector binary would be the primary artifact to detect. Additionally, there are no Sysmon Event ID 8 (CreateRemoteThread) events, which would be the most direct evidence of the injection technique. Memory allocation events (Event ID 9) that might show code injection into the target process are also absent. The WerFault.exe target process exits with status 0x1, suggesting the injection may have failed or been incomplete, though the access attempts were successful.

## Assessment

This dataset provides good coverage of the process execution chain and cross-process access patterns that precede injection attempts. The Security audit logs with command-line logging capture the complete attack flow, while Sysmon Event ID 10 provides the critical process access evidence with detailed call traces. However, the missing CreateRemoteThread events and the actual injector binary execution limit the dataset's completeness for understanding the full injection workflow. The telemetry is excellent for detecting the setup and access phases of process injection but lacks evidence of the actual code injection success.

## Detection Opportunities Present in This Data

1. **Process Access with Full Rights**: Sysmon Event ID 10 showing GrantedAccess 0x1FFFFF from PowerShell to other processes, particularly with System.Management.Automation.dll in the call trace
2. **Suspicious PowerShell Command Lines**: Security Event ID 4688 capturing PowerShell execution with Start-Process and references to Atomic Red Team injection binaries
3. **Cross-Process Access Patterns**: PowerShell processes accessing newly created target processes like WerFault.exe within short time windows
4. **PowerShell Script Block Injection Indicators**: Event ID 4104 containing Start-Process combined with binary execution against process IDs
5. **WerFault.exe as Injection Target**: Process creation of WerFault.exe from non-standard parent processes like PowerShell
6. **Call Trace Analysis**: Sysmon Event ID 10 call traces showing .NET Framework paths leading to process access from automation contexts
