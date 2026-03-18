# T1112-75: Modify Registry — Enforce Smart Card Authentication Through Registry

## Technique Context

T1112 (Modify Registry) is a technique where adversaries modify the Windows Registry to hide configuration information, disable security features, or establish persistence. Registry modification represents one of the most fundamental methods for achieving persistence and defense evasion on Windows systems. The specific test case here focuses on enforcing smart card authentication by modifying the `scforceoption` registry value in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.

The smart card force option (`scforceoption`) is a Group Policy setting that, when enabled, requires smart card authentication for interactive logons. While this is typically a security hardening measure, adversaries might manipulate this setting to either disrupt authentication workflows or potentially create conditions for authentication bypass attacks. Detection engineers focus on monitoring registry modifications to critical authentication and security policy keys, as these changes can indicate both legitimate administrative activity and malicious tampering.

## What This Dataset Contains

This dataset captures a successful registry modification executed through PowerShell spawning cmd.exe which then executes reg.exe. The key process chain is:

- PowerShell (PID 27944) → cmd.exe (PID 22748) → reg.exe (PID 30252)

The registry modification is clearly visible in Sysmon Event ID 13: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\scforceoption` set to `DWORD (0x00000001)`. The Security channel captures the complete process creation chain with command lines, including Security Event ID 4688 for reg.exe with command line `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v scforceoption /t REG_DWORD /d 1 /f`.

Sysmon captures the reg.exe process creation (EID 1) with full command line details and file hashes. The cmd.exe process creation is also captured with its complete command line showing the registry modification command. Process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe processes during execution.

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy, Set-StrictMode scriptblocks) and does not reveal the actual test script content.

## What This Dataset Does Not Contain

This dataset does not contain any blocked execution telemetry - all processes executed successfully with exit status 0x0. There are no Windows Defender detections or quarantine events, indicating the registry modification was not flagged as malicious by the endpoint protection solution.

The dataset lacks any network activity, file system changes beyond temporary PowerShell profile files, or additional persistence mechanisms. Since this is a simple registry modification test, there are no secondary payloads, scheduled tasks, or service installations that might accompany more sophisticated persistence techniques.

The Sysmon ProcessCreate events for the parent PowerShell processes are missing due to the sysmon-modular include-mode filtering, but the Security 4688 events provide complete process creation coverage with command lines.

## Assessment

This dataset provides excellent visibility into registry modification attacks targeting authentication policies. The combination of Sysmon Event ID 13 (registry value set), Security 4688 (process creation with command lines), and Sysmon Event ID 1 (process create for reg.exe) creates comprehensive detection coverage.

The registry modification to `scforceoption` is captured with precise timing, process attribution, and the exact value set. The process chain from PowerShell through cmd.exe to reg.exe is fully documented, providing clear indicators for both signature-based and behavioral detection approaches.

The dataset would be stronger with the actual PowerShell script content in the PowerShell channel, but the process-level telemetry and registry modification events provide sufficient detail for effective detection engineering.

## Detection Opportunities Present in This Data

1. **Registry modification to authentication policies** - Sysmon EID 13 showing writes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\scforceoption`

2. **Reg.exe execution with authentication policy targets** - Sysmon EID 1 and Security 4688 showing reg.exe with command line targeting the System policies registry key

3. **PowerShell spawning system administration tools** - Process chain analysis showing powershell.exe → cmd.exe → reg.exe execution sequence

4. **Modification of security-relevant registry keys** - Registry writes to the `\Policies\System` hive which controls Windows security behavior

5. **Command line pattern matching** - Detection of `reg add` commands targeting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` with specific authentication-related values

6. **Process access patterns** - Sysmon EID 10 showing PowerShell accessing newly spawned processes during registry modification workflows

7. **Administrative tool execution from scripting engines** - Cross-process relationship between PowerShell and legitimate Windows administration utilities being used for registry manipulation
