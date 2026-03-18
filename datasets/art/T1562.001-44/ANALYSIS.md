# T1562.001-44: Disable or Modify Tools — HVCI

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) covers actions that weaken or remove defensive capabilities. This test targets Hypervisor-Enforced Code Integrity (HVCI), a Windows Virtualization Based Security (VBS) feature that uses the hypervisor to validate kernel code integrity. Disabling HVCI via registry allows unsigned or tampered drivers to load into the kernel, a prerequisite for many rootkit and kernel-mode exploit techniques. The change takes effect on next reboot. This is a configuration tampering technique, not a runtime evasion — its primary value to an attacker is removing a kernel protection that would otherwise block their subsequent payloads.

## What This Dataset Contains

The test writes a REG_DWORD value of 0 to `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` using `reg.exe`. The execution chain is visible across all three log sources:

**Security (4688):** Two process creation events capture the full execution chain. A parent PowerShell process (PID 0x161c) spawns a child PowerShell with the command:
```
"powershell.exe" & {reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f}
```
That child PowerShell (PID 0x418) then spawns `reg.exe` with:
```
"C:\Windows\system32\reg.exe" add HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity /v Enabled /t REG_DWORD /d 0 /f
```
A Security 4703 event records the test framework PowerShell process enabling a broad set of privileges including `SeLoadDriverPrivilege` and `SeSystemEnvironmentPrivilege`, which are relevant for VBS/UEFI configuration changes.

**Sysmon:** Event ID 1 (Process Create) captures both the child PowerShell invocation and `reg.exe` with the full command line. Event ID 17 (Pipe Created) records the named pipe `\PSHost.*` for each PowerShell instance. Multiple Event ID 7 (Image Loaded) events show `.NET` runtime and Defender DLLs loading into the test framework PowerShell — this is normal PowerShell initialization noise.

**PowerShell (4104):** Script block logging captures the technique command in two forms — the outer wrapper `& {reg add "HKLM\...\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f}` and the inner block text — along with a `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` event from the ART test framework.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 (RegistryValue Set):** The Sysmon sysmon-modular configuration's registry monitoring rules did not match the `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` path. The write succeeded (reg.exe exited 0x0), but the registry modification itself is only visible through the `reg.exe` command line, not a dedicated registry event.

**No UEFI/firmware change events:** HVCI is also configurable via UEFI settings. Only the registry path is exercised here.

**No reboot-time enforcement events:** HVCI is enforced at boot. No events capturing whether the change takes effect are present.

**No Defender tamper alerts:** Defender did not block this registry write. The HVCI registry key is not protected by Tamper Protection in the same way as Defender's own configuration keys.

## Assessment

The technique executed successfully. The `reg.exe` process exited with status 0x0. The dataset provides good process creation telemetry across both Security 4688 and Sysmon Event 1, with the full command line including the target registry path visible in both. The PowerShell script block captures the technique intent. The absence of a Sysmon 13 event for this specific key is a realistic coverage gap that analysts should be aware of — the command line is the primary detection surface here.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1:** `reg.exe` process creation with command line containing `DeviceGuard` and `HypervisorEnforcedCodeIntegrity` and `/d 0` — high fidelity indicator
- **PowerShell 4104:** Script block text containing `HypervisorEnforcedCodeIntegrity` with value `0`
- **Security 4688:** PowerShell spawning PowerShell (nested invocation) as part of the ART test framework execution pattern — this is a weaker, noisier signal but present
- **Security 4703:** `SeLoadDriverPrivilege` enablement in the same process context as the HVCI write — correlatable temporal signal
- **Sysmon 1 parent-child chain:** `powershell.exe → powershell.exe → reg.exe` for a registry write to a security-sensitive path is a detectable pattern
