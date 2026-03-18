# T1112-56: Modify Registry — Tamper Windows Defender Protection

## Technique Context

T1112 (Modify Registry) targeting Windows Defender's TamperProtection setting is one of the highest-impact registry modifications an attacker can attempt. This test attempts to set `TamperProtection` to `0` under `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`, which would disable Defender's tamper protection mechanism.

Tamper protection is a feature introduced in Windows 10 1903 that prevents unauthorized changes to Windows Defender settings, real-time protection, and related security configurations. With tamper protection enabled, even a SYSTEM-level process cannot modify Defender's core settings through the registry or PowerShell — attempts are silently rejected or blocked. Disabling tamper protection is therefore a prerequisite for subsequently disabling Defender itself, modifying its exclusions, or changing its detection behavior through the registry.

This technique is a common first step in ransomware deployment playbooks. Threat actors including LockBit, BlackCat, and others have used `reg.exe` or scripted approaches to attempt TamperProtection disablement before proceeding to disable real-time protection. The technique does not always succeed — on modern Windows 11 with tamper protection enabled, this registry write will be rejected — but the attempt itself is a high-fidelity indicator of adversarial intent.

In this undefended dataset, Defender is disabled. The registry write may therefore succeed (there is no Defender to enforce tamper protection), but the operational value of this modification is reduced when Defender is already off. This is characteristic of a scripted playbook running regardless of current Defender state.

In the defended variant, this dataset produced 35 Sysmon, 12 Security, and 34 PowerShell events. The undefended capture produced 17 Sysmon, 4 Security, and 36 PowerShell events — nearly identical counts, suggesting the technique had similar execution profiles in both environments.

## What This Dataset Contains

The process creation chain is fully captured. Sysmon EID 1 shows `cmd.exe` (PID 3080) spawned by PowerShell (PID 6748) with:

```
"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f
```

`cmd.exe` spawned `reg.exe` (PID 4464) with:

```
reg  add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f
```

Security EID 4688 independently records both spawns with full command lines and `NT AUTHORITY\SYSTEM` as the executing account.

Sysmon EID 10 records PowerShell accessing `whoami.exe` and `cmd.exe`. The pre-execution `whoami.exe` (PID 4220) is captured in both Sysmon EID 1 and Security EID 4688.

The PowerShell channel (36 EID 4104 events) contains ART test framework boilerplate and a cleanup call: `Invoke-AtomicTest T1112 -TestNumbers 56 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events. The `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` path is not monitored for registry changes by the sysmon-modular configuration. This is a significant gap — the core technique action (the registry write) is not recorded in registry telemetry, only inferred from process execution.

Importantly, there is no evidence in this dataset of whether the registry write succeeded or was rejected. On a system with Defender active and tamper protection enabled, this write would be silently discarded. On this undefended system, it likely succeeded — but neither outcome is confirmed through observable registry events in the collected telemetry.

The dataset contains no Defender event log entries and no Application event log entries indicating Defender reconfigured itself or rejected the modification.

## Assessment

This dataset is notable for what it does not show as much as what it does. The command line evidence in Security EID 4688 and Sysmon EID 1 is unambiguous: an attempt was made to set `TamperProtection` to `0` in the Windows Defender Features key. That attempt is recorded. Whether it succeeded is not directly observable in this telemetry — but the intent is fully documented.

For defenders, the practical lesson here is that the command-line telemetry is sufficient to identify the attack regardless of outcome. An attacker who attempts to disable TamperProtection and succeeds represents a greater risk, but even a failed attempt indicates the adversary's goals and warrants immediate response.

The near-identical event counts between the defended (35/12/34) and undefended (17/4/36) variants suggest this specific technique did not trigger significant Defender activity in the defended run either — TamperProtection enforcement in Windows 11 may block the registry write silently without generating substantial additional telemetry.

## Detection Opportunities Present in This Data

**`reg.exe` targeting `Windows Defender\Features\TamperProtection`.** The value name `TamperProtection` in combination with the path `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` and value `/d 0` is an unambiguous TamperProtection disable attempt. This indicator applies regardless of whether the write succeeds.

**Any write to `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`.** Monitoring the entire `Features` key for writes from non-Defender processes provides broad coverage of Defender feature manipulation attempts.

**Process creation of `reg.exe` with `Windows Defender` in command line arguments.** `reg.exe` being used to modify any `Windows Defender` registry path is suspicious by default, particularly when launched from a PowerShell → cmd.exe chain under SYSTEM.

**Clustering with companion techniques.** This test ran within the same minute as T1112-51 (Defender notifications) and T1112-55 (Windows Update blocking). Multiple `reg add` calls targeting distinct Defender and security policy paths within a short window is a strong behavioral cluster — the individual events reinforce each other.
