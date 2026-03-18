# T1222.001-5: Windows File and Directory Permissions Modification — Grant Full Access to folder for Everyone - Ryuk Ransomware Style

## Technique Context

T1222.001 (Windows File and Directory Permissions Modification) is a defense evasion technique where attackers modify file and directory permissions to maintain access, hide activities, or prepare for data destruction. This specific test emulates Ryuk ransomware's permission modification behavior, using `icacls.exe` to grant "Everyone" full access (F) to all files and folders under `C:\Users\Public\*` recursively. Ransomware groups commonly perform this action before encryption to ensure they can access and modify files regardless of original permissions. Detection engineers focus on monitoring LOLBin usage of `icacls.exe` with suspicious permission grants, especially when targeting broad directory structures or granting "Everyone" elevated permissions.

## What This Dataset Contains

This dataset captures the complete execution chain of the Ryuk-style permission modification attack. The key evidence includes:

**Process Chain Evidence (Sysmon EID 1 & Security EID 4688):**
- PowerShell spawning `cmd.exe` with command line: `"cmd.exe" /c icacls "C:\Users\Public\*" /grant Everyone:F /T /C /Q`
- CMD spawning `icacls.exe` with command line: `icacls  "C:\Users\Public\*" /grant Everyone:F /T /C /Q`
- All processes executed as NT AUTHORITY\SYSTEM with full privileges

**Command Line Details:**
The `icacls` command uses multiple flags consistent with ransomware behavior:
- `/grant Everyone:F` - grants full access to the Everyone group
- `/T` - applies changes recursively to all subdirectories 
- `/C` - continues processing despite errors
- `/Q` - suppresses output for stealth

**Process Access Events (Sysmon EID 10):**
PowerShell accessing both `whoami.exe` and `cmd.exe` with full access rights (0x1FFFFF), showing the parent-child process relationships.

**Privilege Escalation (Security EID 4703):**
Token rights adjustment enabling multiple high-privilege rights including SeBackupPrivilege, SeRestorePrivilege, and SeTakeOwnershipPrivilege.

## What This Dataset Does Not Contain

This dataset lacks several important elements for comprehensive detection:

**File System Changes:** No object access auditing was enabled, so there are no Security EID 4670 events showing the actual permission changes made by `icacls.exe`. This is a significant gap since the core malicious activity (permission modifications) isn't directly captured.

**Process Create for PowerShell:** Sysmon's filtered ProcessCreate configuration didn't capture the initial PowerShell process creation, only the subsequent LOLBin executions (`whoami.exe`, `cmd.exe`, `icacls.exe`).

**Network Activity:** No network connections are present since this is a local file system operation.

**Registry Changes:** The technique doesn't involve registry modifications, so no registry events are expected.

## Assessment

This dataset provides good process execution telemetry for detecting the LOLBin usage patterns typical of ransomware permission modification, but lacks the file system auditing needed to see the actual permission changes. The Sysmon process creation events with command-line details are the strongest detection artifacts, clearly showing the suspicious `icacls` usage with "Everyone" grants. The Security channel's process creation events provide redundant but valuable command-line logging. However, without object access auditing (Security EID 4670), defenders cannot confirm that permission changes actually occurred or see which specific files were affected. This is a common limitation when file system auditing isn't configured.

## Detection Opportunities Present in This Data

1. **ICACLS LOLBin Abuse:** Monitor Sysmon EID 1 for `icacls.exe` execution with command lines containing `/grant Everyone:F`, especially with recursive flags (`/T`)

2. **Suspicious Permission Grants:** Alert on Security EID 4688 process creation events where `icacls.exe` command lines grant broad permissions to "Everyone" group

3. **Ransomware-Style Command Patterns:** Detect `icacls` usage with the specific flag combination `/grant Everyone:F /T /C /Q` which matches known ransomware TTPs

4. **PowerShell-to-CMD-to-ICACLS Chain:** Build detection logic for the process tree: `powershell.exe` → `cmd.exe` → `icacls.exe` with permission modification commands

5. **Privilege Token Adjustments:** Monitor Security EID 4703 for processes enabling SeBackupPrivilege and SeRestorePrivilege in combination with subsequent LOLBin execution

6. **Mass Directory Targeting:** Alert when `icacls` targets broad directory structures like `C:\Users\Public\*` or other user data locations

7. **Process Access with Full Rights:** Use Sysmon EID 10 to detect PowerShell processes accessing newly created processes with full access rights (0x1FFFFF) as potential process injection preparation
