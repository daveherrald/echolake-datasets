# T1518.001-10: Security Software Discovery — Windows Firewall Enumeration

## Technique Context

T1518.001 (Security Software Discovery) encompasses reconnaissance of host-based security controls. Firewall enumeration is a specific sub-objective: adversaries query Windows Firewall profile state and rule configuration to understand which network traffic paths are allowed or blocked. This intelligence directly informs C2 protocol selection, lateral movement techniques, and data exfiltration vectors. A disabled or permissive firewall profile is also evidence that the target may have been pre-configured for easier exploitation or has a weak security posture.

This test uses three `NetSecurity` module cmdlets — `Get-NetFirewallProfile`, `Get-NetFirewallSetting`, and `Get-NetFirewallRule` — which are built-in, require no elevated privileges for read operations, and return comprehensive firewall configuration without touching the disk or spawning external processes.

In the defended variant (47 Sysmon, 14 Security, 39 PowerShell), the test ran without interference. These PowerShell networking cmdlets do not trigger AMSI blocks. The undefended dataset (139 events total) is structurally comparable.

## What This Dataset Contains

The dataset spans approximately 8 seconds (2026-03-17 17:05:24–17:05:32 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 139 events across four channels: 101 PowerShell, 33 Sysmon, 4 Security, and 1 Application.

**Security (4 events, EID 4688):** Four process creation events. The test framework `whoami.exe` pre-flight is first. The second is the defining event: a child `powershell.exe` spawned with the full enumeration command line:

```
"powershell.exe" & {Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallSetting
Get-NetFirewallRule | select DisplayName, Enabled, Description}
```

The parent is the SYSTEM-context test framework `powershell.exe` at PID `0x4700`. The post-execution `whoami.exe` and cleanup `powershell.exe` complete the four events.

**Sysmon (33 events, EIDs 1, 7, 10, 11, 17):** Sysmon EID 1 captures both the test framework `whoami.exe` (tagged `T1033`) and the firewall enumeration `powershell.exe` (tagged `T1083,File and Directory Discovery` — the same sysmon-modular classification artifact seen in T1518.001-9). The full three-cmdlet command line is preserved verbatim in the EID 1 record.

EID 7 records 22 DLL load events into the PowerShell processes. In the defended variant, Defender's `MpOAV.dll` and `MpClient.dll` were visible in EID 7; those are absent here (Defender disabled). EID 10 fires four times (ProcessAccess, `T1055.001`, GrantedAccess `0x1FFFFF`). EID 17 records two named pipe creates. EID 11 records one file creation in the SYSTEM profile path.

**PowerShell (101 events, EIDs 4103, 4104):** All 101 events are test framework overhead: `Set-ExecutionPolicy Bypass` in EID 4103 and internal formatter stubs in EID 4104. The three firewall cmdlets were passed inline in the command line argument and their script block is recorded in the Security EID 4688 and Sysmon EID 1 rather than as a distinct 4104 entry in the surfaced samples. EID 4100 is not present (no error, indicating the firewall cmdlets ran successfully).

**Application (1 event, EID 15):** `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — the same Security Center background state event seen in T1518-5 and T1518-6, reflecting periodic OS state tracking rather than technique behavior. In the defended variant, EID 15 also appeared as part of the captured events.

## What This Dataset Does Not Contain

- **No firewall rule output.** The configured rules on ACME-WS06, the profiles' enabled state, and the global settings are not captured in event logs. Only the invocation is recorded.
- **No Defender DLL loads.** The defended variant's Sysmon EID 7 would show `MpOAV.dll` loading into the `NetSecurity`-invoking PowerShell process; those are absent here.
- **No network events.** Firewall enumeration via `NetSecurity` cmdlets is purely local; no TCP connections are generated.
- **No EID 5156 (Windows Filtering Platform: permitted connection) or EID 5157 (blocked connection).** These network platform events are not captured in this dataset's audit policy configuration.
- **No notable observable difference vs. the defended variant.** Like T1518.001-7 and T1518.001-9, the firewall enumeration cmdlets do not trigger Defender blocks, making the defended and undefended profiles nearly identical at the command-line evidence level.

## Assessment

Firewall enumeration using `Get-NetFirewallProfile`, `Get-NetFirewallSetting`, and `Get-NetFirewallRule` is a low-noise, high-value reconnaissance step that generates minimal telemetry relative to its information yield for an adversary. The only reliable evidence is the command line in Security EID 4688 and Sysmon EID 1.

The undefended dataset is 24 events fewer than the defended variant (139 vs. ~100 for the defended run's comparable sources), though the PowerShell channel is larger in the undefended run (101 vs. 39) due to the higher test framework overhead baseline. The core detection evidence is identical in both variants.

`Get-NetFirewallRule | select DisplayName, Enabled, Description` is the most informative of the three cmdlets for an adversary — it returns every configured firewall rule, potentially revealing what services are exposed. The specificity of this cmdlet combination, when observed in a Security EID 4688 command line from a SYSTEM context, is a strong behavioral indicator.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The three-cmdlet firewall enumeration block is captured verbatim, including all three cmdlet names and their specific format/select arguments. `Get-NetFirewallProfile`, `Get-NetFirewallSetting`, and `Get-NetFirewallRule` appearing together in a single inline command block from a SYSTEM context is a high-specificity pattern.
- **Sysmon EID 1 command line:** Same evidence with process hash and parent chain. The `T1083` tag is a sysmon-modular classification artifact; the command line content is definitive.
- **Parent PowerShell to child PowerShell spawn:** The `powershell.exe → powershell.exe` spawning pattern with security-enumeration cmdlets in the child's command line is consistent across T1518.001-9, -10, and -11, representing a cluster of related discovery techniques with a shared behavioral signature.
- **Application EID 15 (Security Center state):** The presence of this event in both defended and undefended collection windows confirms the Application log channel is active for this test series. Its value as a detection indicator is low (it is a background event), but it provides a timestamp anchor for correlating other events in the collection window.
