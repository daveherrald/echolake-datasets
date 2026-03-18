# T1134.001-4: Token Impersonation/Theft — Bad Potato

## Technique Context

T1134.001 (Token Impersonation/Theft) involves adversaries creating new access tokens to impersonate other users or escalate privileges. "Potato" exploits are a family of local privilege escalation techniques that abuse Windows authentication mechanisms, typically targeting service accounts or Named Pipe impersonation vulnerabilities. BadPotato specifically targets the BITS (Background Intelligent Transfer Service) to achieve privilege escalation from service account contexts to SYSTEM.

The detection community focuses on monitoring for unusual process access patterns, token manipulation APIs, and the specific behavior signatures of potato exploits including Named Pipe creation, process hollowing, and service impersonation attempts. These techniques are commonly used by adversaries to move from initial foothold to higher privilege contexts.

## What This Dataset Contains

This dataset captures a failed execution attempt of BadPotato. The PowerShell script attempts to execute `Start-Process .\BadPotato.exe notepad.exe` from the ExternalPayloads directory, but the execution fails with PowerShell error 4100: "This command cannot be run due to the error: The system cannot find the file specified."

Key telemetry includes:
- Security event 4688 showing PowerShell process creation with full command line: `"powershell.exe" & {cd \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\"...}`
- PowerShell script block logging (event 4104) capturing the BadPotato execution attempt
- Multiple Sysmon process access events (EID 10) showing PowerShell accessing whoami.exe and other PowerShell processes with high privileges (GrantedAccess: 0x1FFFFF)
- Security event 4703 documenting extensive privilege adjustments including SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and other token-related privileges
- Sysmon process creation (EID 1) for both whoami.exe and the child PowerShell process
- Standard .NET Framework and PowerShell DLL loading patterns in Sysmon image load events

## What This Dataset Does Not Contain

The dataset lacks the core BadPotato exploitation artifacts because the BadPotato.exe binary is not present in the expected location. This results in:
- No actual token impersonation or privilege escalation activity
- No Named Pipe creation specific to BadPotato exploitation
- No service impersonation attempts or BITS service interaction
- No suspicious process hollowing or injection beyond standard PowerShell operations
- Missing the characteristic network activity or inter-process communication that BadPotato typically generates

The Sysmon configuration's include-mode filtering means we also don't see certain process creations that might be part of a successful BadPotato chain.

## Assessment

This dataset provides limited value for detecting actual BadPotato exploitation since the technique execution failed before reaching the privilege escalation phase. However, it offers valuable telemetry for detecting preparation phases and failed exploitation attempts. The Security 4703 event showing privilege adjustments and the Sysmon process access events demonstrate the monitoring capabilities available for token manipulation detection. The complete PowerShell command line capture in Security 4688 events provides excellent visibility into the attack intent, even when execution fails.

For building robust BadPotato detections, this dataset would need to be supplemented with successful execution examples that show the full technique lifecycle.

## Detection Opportunities Present in This Data

1. **PowerShell execution with BadPotato references** - Security 4688 and PowerShell 4104 events containing "BadPotato.exe" in command lines or script blocks
2. **Suspicious privilege adjustments** - Security 4703 events showing simultaneous enablement of SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege
3. **High-privilege process access patterns** - Sysmon 10 events where PowerShell accesses other processes with 0x1FFFFF (full access) permissions
4. **PowerShell process spawning from PowerShell** - Sysmon 1 events showing powershell.exe creating child powershell.exe processes with suspicious command lines
5. **Failed malware execution attempts** - PowerShell 4100 error events indicating file not found for known exploit tools
6. **Atomic Red Team execution patterns** - Command lines referencing "AtomicRedTeam\atomics\..\ExternalPayloads" paths indicating testing or attack tool usage
7. **System context PowerShell with external tool execution attempts** - Security 4688 events showing SYSTEM account PowerShell attempting to launch external executables
