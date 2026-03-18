# T1562.001-48: Disable or Modify Tools — Tamper with Windows Defender Registry - Reg.exe

## Technique Context

MITRE ATT&CK T1562.001 covers disabling or modifying security tools. This test uses `reg.exe` to write a comprehensive set of Windows Defender policy registry values that disable nearly every Defender protection component. The values are written to `HKLM\Software\Policies\Microsoft\Windows Defender` and its subkeys (`Real-Time Protection`, `Reporting`, `SpyNet`, `MpEngine`) using the Group Policy path rather than the direct Defender settings path, which can bypass Tamper Protection on versions where policy keys are less strictly guarded. This is a bulk disablement technique — 14 separate registry writes covering real-time protection, behavior monitoring, IOAV, script scanning, cloud submission, PUA protection, and more.

## What This Dataset Contains

The dataset contains 14 `reg.exe` process creation events (Security 4688, Sysmon 1) each writing a specific Defender-disabling value, plus corresponding Sysmon 13 (RegistryValue Set) confirmation events. The full set of written values includes:

- `HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiVirus = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIntrusionPreventionSystem = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRoutinelyTakingAction = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\Reporting\DisableEnhancedNotifications = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet\DisableBlockAtFirstSeen = 1`
- `HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet\SpynetReporting = 0`
- `HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine\MpEnablePus = 0`

Additional writes attempt `DisallowExploitProtectionOverride = 0`, `TamperProtection = 0`, `SubmitSamplesConsent = 0`, and `PUAProtection = 0`.

Each reg.exe invocation is captured in both Security 4688 (with full command line) and Sysmon 1. Sysmon 13 events confirm the registry writes to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\*`. The Security log also records the parent `cmd.exe` spawning `reg.exe` for each write.

## What This Dataset Does Not Contain (and Why)

**No Defender service stop or restart:** Writing policy registry values does not immediately disable running Defender components — a service restart or reboot is typically required for most values to take effect. No `sc.exe stop` or service-related events are present.

**No TamperProtection bypass confirmation:** The `TamperProtection` write to `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection` (note: not the policy path) is attempted. Sysmon 13 does not record a successful write for this key, which is strongly protected by Defender Tamper Protection even for SYSTEM processes.

**No Security 4656/4663 (object access):** The audit policy has object access auditing disabled, so no object-level access events for registry keys are present.

**No Sysmon 12/13 for the `HKLM\SOFTWARE\Microsoft\Windows Defender` path:** The Tamper Protection keys under the non-policy path were not captured by Sysmon 13, suggesting either Tamper Protection blocked the write or the Sysmon config does not cover that path with registry monitoring.

## Assessment

The technique executed comprehensively. The 14 bulk policy writes to `HKLM\Software\Policies\Microsoft\Windows Defender` and subkeys completed with `reg.exe` exit code 0x0. The Sysmon 13 events confirm the writes landed in the registry. This dataset is notable for the breadth of values written in a single test, making it representative of a "scorched earth" Defender disablement pattern used by commodity malware. Detection relies on recognizing the policy key path pattern, as Tamper Protection does not cover the `Policies` hive on all configurations.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1:** `reg.exe` with `SOFTWARE\Policies\Microsoft\Windows Defender` and `Disable` or `/d 1` in the command line — high-confidence Defender policy tampering
- **Sysmon 13:** Registry writes to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\*` with value 1 (disable) — direct confirmation of policy write
- **Volume heuristic:** 14+ `reg.exe` process creations within a 5-second window, all targeting `Windows Defender` policy subkeys — burst pattern is highly anomalous
- **Security 4688:** `cmd.exe` parent spawning a sequence of `reg.exe` children all targeting the same key subtree
- **Sysmon 1 + 13 correlation:** Cross-source correlation of process creation to registry write confirms the full attack chain
