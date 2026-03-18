# T1112-51: Modify Registry — Disable Windows Defender Notification

## Technique Context

T1112 (Modify Registry) targeting Windows Defender's notification system represents a targeted defense evasion operation. This test sets `DisableNotifications` to `1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications`, which suppresses user-visible security alerts from Windows Defender Security Center.

The `Policies\Microsoft\Windows Defender Security Center` registry path is the Group Policy-controlled location for Defender configuration. Writing values here mimics Group Policy enforcement — Windows treats values under `Policies` with authority, often overriding per-user and per-machine settings. By disabling notifications through this policy path, an attacker can cause Windows Defender to silently detect and log threats without alerting the user, reducing the chance of manual intervention while security operations continue.

This differs from the direct Defender configuration path (`HKLM\SOFTWARE\Microsoft\Windows Defender`) in that the Policies path is typically managed by enterprise Group Policy. Writing to it from a script implies either a compromised domain controller pushing policy, a local administrator bypassing group policy, or an attacker operating under a high-privilege account.

The attack targets user-visible alerting, not Defender's detection capability itself. Combined with other techniques in this session (disabling TamperProtection in T1112-56, disabling Windows Update in T1112-55), a full picture emerges of an attacker systematically degrading the endpoint's security posture.

In the defended variant, this dataset produced 28 Sysmon, 12 Security, and 34 PowerShell events. The undefended capture produced 18 Sysmon, 4 Security, and 50 PowerShell events.

## What This Dataset Contains

The registry modification is captured directly in Sysmon EID 13:

```
Registry value set:
TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications\DisableNotifications
Details: DWORD (0x00000001)
User: NT AUTHORITY\SYSTEM
```

This event confirms the write succeeded and provides the exact path and value. The value `1` enables the notification suppression policy.

The process creation chain is recorded in Sysmon EID 1 and Security EID 4688. `cmd.exe` (PID 3676) was spawned by PowerShell (PID 1144) with:

```
"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f
```

`cmd.exe` spawned `reg.exe` (PID 5100) with:

```
reg  add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f
```

Both events appear in Security EID 4688 with SYSTEM as the executing account and `C:\Windows\TEMP\` as the `cmd.exe` working directory.

Sysmon EID 10 records PowerShell accessing child processes. The Sysmon EID 7 events show the standard PowerShell DLL load sequence.

The PowerShell channel (50 EID 4104 events) contains ART test framework boilerplate, including a cleanup invocation: `Invoke-AtomicTest T1112 -TestNumbers 51 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

The dataset does not contain Windows Defender event log entries reflecting the policy change. You would expect entries in `Microsoft-Windows-Windows Defender/Operational` when Defender policy is modified, but those events are not included in this dataset's bundled files.

The dataset does not show any security alerts that were being suppressed — there is no evidence of what threats Defender may have been detecting silently in the background. The notification suppression mechanism takes effect prospectively; existing alert history is not affected.

There are no Application or System event log entries related to Group Policy processing or the Defender service reconfiguring in response to the registry change.

The initial ART test framework PowerShell processes are absent from Sysmon EID 1 due to include-mode filtering.

## Assessment

This dataset provides two-source confirmation of the technique: Sysmon EID 13 directly records the registry write, and Security EID 4688 plus Sysmon EID 1 capture the command line from which the write was initiated. The Defender Notifications policy path is specific enough that the presence of a `reg add` targeting it is a high-fidelity indicator.

The fact that this technique ran while Defender was already disabled (as indicated by the dataset's "undefended" classification) is worth noting: the attacker is modifying notification policies even in an environment where Defender itself is off. This suggests either an automated playbook running without awareness of the current Defender state, or pre-staging for when Defender is re-enabled.

Compared to the defended variant, the structure is identical. The undefended run shows the same chain with fewer Security events and more PowerShell events.

## Detection Opportunities Present in This Data

**Sysmon EID 13 on `Windows Defender Security Center\Notifications\DisableNotifications`.** The specific path and value name are targeted enough that any write here warrants investigation. The `Policies` path makes this particularly suspicious when it originates from a script rather than Group Policy enforcement.

**`reg.exe` command line containing `Windows Defender Security Center\Notifications`.** The full path in the `reg add` arguments is unambiguous. Both Sysmon EID 1 and Security EID 4688 capture this.

**Writes to the `Policies\Microsoft\Windows Defender` registry tree from non-GPO processes.** Legitimate Group Policy writes to this path come from `lsass.exe` or the Group Policy client; `reg.exe` writing here under SYSTEM from a TEMP directory is anomalous.

**Cluster with other Defender policy modifications.** In the broader session, T1112-51 (DisableNotifications), T1112-56 (TamperProtection), and T1112-55 (Windows Update) ran within seconds of each other. Detecting two or more writes to `Policies\Microsoft\Windows Defender` or related paths within a short window is a strong behavioral cluster indicator for ransomware preparation activity.
