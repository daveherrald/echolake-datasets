# T1112-45: Modify Registry — Enabling Restricted Admin Mode via Command Prompt

## Technique Context

T1112 (Modify Registry) targeting the Local Security Authority (LSA) configuration is a high-value operation for attackers because LSA controls authentication, credential handling, and security policy enforcement on Windows. This test sets `DisableRestrictedAdmin` to `0` under `HKLM\System\CurrentControlSet\Control\Lsa`, which enables Restricted Admin Mode for Remote Desktop Protocol connections.

Restricted Admin Mode changes how RDP handles credentials. When enabled, RDP authentication occurs using a network logon rather than delegating credentials to the remote host. This is significant for attackers because Pass-the-Hash attacks against RDP become viable — an attacker with a NTLM hash but not the plaintext password can authenticate to systems via RDP when Restricted Admin Mode is enabled, without needing to crack the hash. The technique is used by threat actors to enable lateral movement with harvested credentials.

The registry path `HKLM\System\CurrentControlSet\Control\Lsa` is among the most security-sensitive registry locations on Windows. It controls LsaProtection, credential isolation, authentication packages, and related security settings. Modifications here are inherently high-fidelity indicators of suspicious activity.

Sysmon's rule tagging in this dataset labels the `reg.exe` and `cmd.exe` process creations with `technique_id=T1083`, which reflects the sysmon-modular ruleset's pattern matching rather than a precise technique attribution — the actual behavior here is LSA tampering, not file discovery. The critical evidence is in the command-line arguments, not the rule labels.

In the defended variant, this dataset produced 28 Sysmon, 12 Security, and 34 PowerShell events. The undefended capture produced 18 Sysmon, 4 Security, and 93 PowerShell events. The PowerShell event count increase is substantial — 93 vs 34 — reflecting that the ART test framework generated more script block fragments without Defender's interception of certain test framework phases.

## What This Dataset Contains

The registry write is captured directly in Sysmon EID 13:

```
Registry value set:
TargetObject: HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin
Details: DWORD (0x00000000)
User: NT AUTHORITY\SYSTEM
```

Setting `DisableRestrictedAdmin` to `0` enables the feature (the value name is the inverse of the behavior — disabling the "disable" flag turns Restricted Admin on).

Sysmon EID 1 captures the full process chain. `cmd.exe` (PID 4472) was spawned by PowerShell (PID 3120) with:

```
"cmd.exe" /c reg add "hklm\system\currentcontrolset\control\lsa" /f /v DisableRestrictedAdmin /t REG_DWORD /d 0
```

`cmd.exe` spawned `reg.exe` (PID 7124) with:

```
reg  add "hklm\system\currentcontrolset\control\lsa" /f /v DisableRestrictedAdmin /t REG_DWORD /d 0
```

Security EID 4688 records both process creations independently. The `cmd.exe` event shows Creator Process as PowerShell and the full command line with the lowercase path `hklm\system\currentcontrolset\control\lsa` — note the lowercase, which is how the ART atomic defines it and which `reg.exe` accepts without case sensitivity.

Sysmon EID 10 shows PowerShell accessing child processes with access mask `0x1FFFFF` (full access). Sysmon EID 7 records multiple DLL loads into PowerShell.

## What This Dataset Does Not Contain

The PowerShell channel (93 EID 4104 events) contains only ART test framework boilerplate and no PowerShell code for the actual registry modification. The technique was implemented via `cmd.exe`/`reg.exe` rather than `Set-ItemProperty`, so no meaningful PowerShell script block captures the LSA modification.

The dataset does not contain any Sysmon EID 12 (registry key create) events alongside the EID 13 (value set). The key `Lsa` already exists; only the new value `DisableRestrictedAdmin` was added.

There is no RDP-related telemetry and no authentication events. The dataset captures only the registry preparation step, not any subsequent Pass-the-Hash activity that the modification might facilitate.

The initial ART test framework PowerShell processes are not visible in Sysmon EID 1 due to the include-mode filtering in sysmon-modular. Only `cmd.exe`, `reg.exe`, and `whoami.exe` appear in process creation events.

## Assessment

This dataset provides strong, multi-source evidence of LSA configuration tampering. The Sysmon EID 13 directly records the value name and data written to `HKLM\System\CurrentControlSet\Control\Lsa`, and Security EID 4688 plus Sysmon EID 1 capture the full command line from which the intent can be read without ambiguity.

The undefended execution matches the defended variant's structure exactly — the same process chain, the same command line, the same result. The absence of Defender means no blocking attempt and no remediation activity, which is why the Sysmon event count is lower despite the higher PowerShell count.

The technique completed successfully: the registry write occurred (confirmed by EID 13), and no error indicators appear in either process creation or PowerShell logs.

## Detection Opportunities Present in This Data

**Sysmon EID 13 on `Lsa\DisableRestrictedAdmin`.** A registry write setting `DisableRestrictedAdmin` to `0` in `HKLM\System\CurrentControlSet\Control\Lsa` is a precise, high-fidelity indicator with limited legitimate use outside of specific enterprise RDP hardening scenarios — and those scenarios would not typically use `reg.exe` from a TEMP directory under SYSTEM.

**`reg.exe` targeting `control\lsa`.** The substring `control\lsa` in a `reg.exe` command line argument is worth monitoring broadly. Legitimate LSA configuration changes happen through Group Policy or Windows Security configuration tools, rarely through direct `reg add` from a script.

**PowerShell → cmd.exe → reg.exe under SYSTEM with `control\lsa` path.** The three-hop execution chain with SYSTEM token and TEMP working directory, combined with an LSA registry target, represents an unusual combination even when viewed independently from the specific value being written.

**Presence of `DisableRestrictedAdmin` with value `0`.** The value name itself is distinctive. In corporate environments, this key either does not exist (Restricted Admin Mode not configured) or is set to `1` (explicitly disabled). Setting it to `0` to enable the feature is an active operational choice worth alerting on.
