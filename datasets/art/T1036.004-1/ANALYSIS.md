# T1036.004-1: Masquerade Task or Service — Creating W32Time similar named service using schtasks

## Technique Context

T1036.004 (Masquerade Task or Service) is a defense evasion technique where adversaries create services or scheduled tasks with names that masquerade as legitimate system services to blend in with normal system activity. This is a common persistence and defense evasion mechanism, as administrators and security tools often overlook innocuous-sounding service names during routine monitoring.

The detection community focuses on identifying suspicious service/task creation patterns, particularly those with names similar to legitimate Windows services but with slight variations (typos, case changes, extra characters). Key detection opportunities include monitoring for service creation with suspicious names, unusual execution paths, or tasks scheduled with high privileges pointing to non-standard locations.

This specific test creates a scheduled task named "win32times" - a clear attempt to masquerade as the legitimate "w32time" Windows Time Service, adding an extra "s" to appear legitimate while being functionally different.

## What This Dataset Contains

The dataset captures a successful scheduled task masquerading attack with excellent telemetry across multiple event sources:

**Core Technique Evidence:**
- Security 4688 events showing the complete attack chain: `powershell.exe` → `cmd.exe` → `schtasks.exe`
- Sysmon EID 1 events with full command lines showing task creation: `schtasks /create /ru system /sc daily /tr "cmd /c powershell.exe -ep bypass -file c:\T1036.004_NonExistingScript.ps1" /tn win32times /f`
- TaskScheduler EID 106/140 events documenting task registration and update for "\win32times"

**Registry Modifications:**
- Sysmon EID 13 events showing Task Scheduler registry writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\win32times\`
- Registry entries include task ID, index, and security descriptor

**File System Activity:**
- Sysmon EID 11 showing task file creation at `C:\Windows\System32\Tasks\win32times`
- PowerShell startup profile files created during execution

**Process Telemetry:**
- Full process chain with parent-child relationships preserved
- Sysmon EID 10 process access events from PowerShell to spawned processes
- Security 4688/4689 events with complete command line logging

## What This Dataset Does Not Contain

The dataset does not contain evidence of the scheduled task actually executing, as it references a non-existent PowerShell script (`c:\T1036.004_NonExistingScript.ps1`). This means no follow-on persistence behavior is demonstrated - only the creation phase of the masquerading task.

The PowerShell logs contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual technique implementation, as the work is performed by the spawned `schtasks.exe` process rather than PowerShell directly.

No Windows Defender blocks are present - the technique executed successfully without endpoint protection interference.

## Assessment

This dataset provides excellent detection engineering value for T1036.004. The telemetry quality is high across multiple complementary data sources, with Security 4688 providing full command-line visibility, Sysmon adding detailed process relationships and registry modifications, and TaskScheduler logs offering native confirmation of the masquerading task creation.

The "win32times" vs "w32time" naming pattern represents a textbook example of service masquerading that detection engineers should focus on. The dataset would be strengthened by including evidence of the task's execution phase, but the creation phase is thoroughly documented.

## Detection Opportunities Present in This Data

1. **Suspicious Task Names**: Monitor TaskScheduler EID 106 and Sysmon EID 13 registry writes for task names that closely resemble legitimate Windows services (e.g., "win32times" vs "w32time")

2. **Scheduled Task Creation via Command Line**: Detect Security 4688 events for `schtasks.exe` with `/create` and `/tn` parameters, especially with names similar to system services

3. **High-Privilege Task Creation**: Alert on `schtasks.exe` execution with `/ru system` parameter creating tasks that run as SYSTEM

4. **Suspicious Task Actions**: Monitor for scheduled tasks with execution paths pointing to non-standard locations or using PowerShell with bypass execution policy

5. **Registry Modifications in TaskCache**: Detect Sysmon EID 13 registry writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\` with suspicious task names

6. **Process Chain Analysis**: Correlate PowerShell spawning cmd.exe spawning schtasks.exe as an unusual execution pattern

7. **Task File Creation**: Monitor Sysmon EID 11 for file creation in `C:\Windows\System32\Tasks\` with names resembling system services

8. **String Similarity Detection**: Implement fuzzy matching algorithms to identify task names with high similarity to legitimate Windows service names but with character variations
