# T1113-9: Screen Capture — Windows Recall Feature Enabled (DisableAIDataAnalysis Value Deleted)

## Technique Context

T1113 Screen Capture describes adversaries taking screenshots or continuously recording screen content to collect sensitive information displayed on victim systems. While traditional implementations invoke screenshot APIs or third-party capture tools, this test takes a different approach: it manipulates the Windows Recall feature introduced in Windows 11 24H2.

Windows Recall is an AI-powered feature that continuously captures and indexes screen content, creating a searchable history of everything displayed on the machine. From an adversarial perspective, enabling Recall on a compromised system hands the attacker a persistent, automated screen capture mechanism that operates with no visible indicator to the user. The feature is governed by the `DisableAIDataAnalysis` registry value under `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI`. A value of `1` disables Recall; a value of `0` or the absence of the value entirely enables it.

This test simulates the enabling sequence: first adding `DisableAIDataAnalysis` set to `0`, then deleting the value entirely. Both registry states allow Recall to operate. The test uses `reg.exe` driven from PowerShell, which is consistent with how automated tools or post-exploitation frameworks would approach this.

## What This Dataset Contains

The dataset captures 45 Sysmon events, 7 Security events, and 111 PowerShell events recorded on ACME-WS06 (Windows 11 Enterprise, `acme.local`) with Windows Defender fully disabled via Group Policy.

The core technique execution is visible across both the Security and Sysmon channels. Security EID 4688 shows the spawning PowerShell instance launching a child process with the full command:

```
"powershell.exe" & {reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /f}
```

Two subsequent `reg.exe` process creation events (EID 4688) record each registry operation individually:
- `"C:\Windows\system32\reg.exe" add HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI /v DisableAIDataAnalysis /t REG_DWORD /d 0 /f`
- `"C:\Windows\system32\reg.exe" delete HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI /v DisableAIDataAnalysis /f`

Sysmon EID 1 (Process Create) records the same process chain with full image hashes: `powershell.exe` (SHA256: `3247BCFD...`) spawning `reg.exe` (SHA256: deterministic for the Windows system binary). Sysmon EID 10 (Process Accessed) records PowerShell accessing both `reg.exe` instances with `GrantedAccess: 0x1FFFFF`, which is full access — consistent with how PowerShell calls child processes via `CreateProcess`.

Sysmon EID 17 (Pipe Created) records the named pipe `\PSHost.134182389609567173.16428.DefaultAppDomain.powershell` created by the PowerShell host process, which is standard for interactive PowerShell sessions. Sysmon EID 7 (Image Load) captures the .NET runtime DLLs loaded into `powershell.exe` including `mscoree.dll`, `clr.dll`, and `System.Management.Automation.ni.dll`.

The PowerShell channel contains 111 events, predominantly EID 4104 (Script Block Logging). The captured script blocks are largely the ART test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`, `$ErrorActionPreference = 'Continue'`). The actual registry manipulation was executed as a command-line argument rather than a script file, so the specific `reg add`/`reg delete` payload appears in the process creation command lines rather than as a distinct script block capture.

The dataset window spans only 3 seconds (16:36:02Z to 16:36:05Z on 2026-03-17), reflecting the near-instantaneous execution of `reg.exe`.

## What This Dataset Does Not Contain

This dataset does not capture any Windows Recall process activity, snapshot writes, or AI analysis telemetry — the test only enables Recall at the registry policy level; it does not wait for or verify that Recall actually begins capturing. The Windows Recall infrastructure processes (`AIXHostService`, `ScreenshotManager`) are not present in this data.

There are no Security channel registry-specific event IDs (4656, 4657, 4663) because the audit policy on this host does not enable Object Access auditing. The registry modification itself is only observable through process creation events showing `reg.exe` with the target key and value name in the command line.

No network activity is present — this technique is entirely local registry manipulation.

Compared to the defended variant (30 Sysmon / 15 Security / 28 PowerShell), this dataset is larger: 45 Sysmon / 7 Security / 111 PowerShell. The Security channel count is actually lower here (7 vs. 15) because the defended variant generated additional Defender-related process creation events when Defender attempted to inspect or respond to the technique. The Sysmon count increase (45 vs. 30) comes primarily from the additional image load events logged for the second PowerShell child process spawned during execution. The PowerShell channel is significantly larger (111 vs. 28) because, with Defender disabled, AMSI inspection hooks are not present to suppress certain script block logging pathways, resulting in more granular block captures.

## Assessment

This is a high-fidelity dataset for the Recall enablement technique. The key observables are all present: the `reg.exe` command lines naming the target key and value are captured verbatim in both EID 4688 and Sysmon EID 1. A detection author has everything needed to build a precise behavioral signature around `reg.exe` modifying `HKCU\Software\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis`.

The dataset is also representative of how this technique looks in practice. Real-world post-exploitation tools that target Recall (or any AI-feature policy key) would produce the same `reg.exe` child process pattern from a parent scripting host, with the same access rights visible in EID 10. The short time window and compact event count make this an efficient training example for this specific behavior.

The one gap worth noting is the absence of registry auditing. On a host with Object Access auditing enabled, you would see Security EID 4657 (Registry Value Modified) and EID 4663 (Object Accessed) providing a direct registry-level paper trail. Those events are absent here and in the defended variant, which means the dataset reflects what you will see on a typical enterprise host with the default audit policy.

## Detection Opportunities Present in This Data

The following observable behaviors are present in this dataset and support detection development:

**Process creation with reg.exe targeting the WindowsAI policy key.** Both EID 4688 (Security) and EID 1 (Sysmon) record `reg.exe` with the full command line including `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI` and the value name `DisableAIDataAnalysis`. This is a specific and low-prevalence key path; legitimate administrative tooling rarely touches it.

**Deletion of the DisableAIDataAnalysis value.** The `reg delete` invocation is present in EID 4688. Deleting a disable-flag is an uncommon pattern compared to setting it; the delete operation specifically re-enables Recall and is a stronger indicator than the add-with-zero operation.

**PowerShell spawning reg.exe.** Sysmon EID 1 records `powershell.exe` as the `ParentImage` for both `reg.exe` invocations. While PowerShell calling `reg.exe` is not rare in administrative contexts, the combination with the specific WindowsAI key path makes this a high-confidence compound indicator.

**Script block logging capturing the ART invocation structure.** EID 4104 captures `Set-ExecutionPolicy Bypass -Scope Process -Force` and `$ErrorActionPreference = 'Continue'`, which are characteristic of the ART test framework. In a real incident, equivalent overhead from an offensive framework would appear similarly.
