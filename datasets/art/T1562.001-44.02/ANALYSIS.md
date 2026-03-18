# T1562.001-44: Disable or Modify Tools — Disable Hypervisor-Enforced Code Integrity (HVCI)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) covers actions that
weaken or remove defensive capabilities. This test targets Hypervisor-Enforced Code
Integrity (HVCI), also known as Memory Integrity. HVCI is a Windows Virtualization-Based
Security (VBS) feature that uses the hypervisor to enforce that all code loaded into the
kernel is signed and unmodified. Disabling HVCI allows unsigned or tampered kernel-mode
drivers to load, which is a prerequisite for many rootkit and kernel-mode exploit techniques.

The test sets the `Enabled` registry value to `0` under:
```
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
```

This change requires a reboot to take effect. It does not immediately disable HVCI but
configures the system to disable it at the next boot. This is a configuration tampering
technique — its value to an attacker is removing a kernel protection that would otherwise
block subsequent driver-based payloads.

In this **undefended** dataset, Defender is disabled. The registry write succeeds.

## What This Dataset Contains

The dataset captures 103 events across two channels (99 PowerShell, 4 Security) spanning
approximately 3 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17).

**Security EID 4688 — Four process creation events capturing the full execution chain:**

1. `"C:\Windows\system32\whoami.exe"` — pre-execution ART identity check, parent is the
   ART test framework PowerShell (`NT AUTHORITY\SYSTEM`)
2. `"powershell.exe" & {reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f}` — child PowerShell spawned by the ART test framework to run the reg.exe command
3. `"C:\Windows\system32\reg.exe" add HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity /v Enabled /t REG_DWORD /d 0 /f` — reg.exe spawned by the child PowerShell (not by cmd.exe), parent is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
4. `"C:\Windows\system32\whoami.exe"` — post-execution ART identity check

The full registry path, value name (`Enabled`), type (`REG_DWORD`), and data (`0`) are
all directly readable in both the child PowerShell 4688 command line (event 2) and the
`reg.exe` 4688 command line (event 3). Note that `reg.exe` is spawned directly from
PowerShell here — there is no `cmd.exe` intermediate, distinguishing this pattern from the
cmd.exe-based registry tests (32 and 33).

The parent for the child PowerShell (event 2) is a PowerShell process, and the parent for
`reg.exe` (event 3) is also PowerShell — confirming a PowerShell → PowerShell → reg.exe
chain, not a PowerShell → cmd.exe → reg.exe chain.

**PowerShell EID 4104 — 98 script block events.** The substantive blocks are the ART
test framework boilerplate and the cleanup invocation:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 44 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

Additional standard boilerplate: `Set-ExecutionPolicy Bypass -Scope Process -Force` and
`$ErrorActionPreference = 'Continue'`.

**PowerShell EID 4103 — One module pipeline event** for `Set-ExecutionPolicy`.

**No EID 4100 error events.** `reg.exe` completed with exit status `0x0`. The registry
write succeeded.

## What This Dataset Does Not Contain

**No Sysmon events.** The bundled channels are PowerShell/Operational and Security only.
The defended dataset includes Sysmon EID 1 (process creates for `whoami.exe`, child
`powershell.exe`, and `reg.exe`), EID 7 (image loads — .NET runtime and Defender DLLs),
EID 17 (named pipe creation for `\PSHost.*` PowerShell instances), and EID 4703 (token
privilege adjustment for `SeLoadDriverPrivilege` and `SeSystemEnvironmentPrivilege`). None
of those appear here.

**No Sysmon EID 13 (registry value set).** The DeviceGuard registry path
`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` is not in the sysmon-modular EID 13
include rules. The modification is only visible through the `reg.exe` command line in 4688.

**No Security EID 4703 (token right adjustment).** In the defended variant, a 4703 event
captures the test framework PowerShell enabling `SeLoadDriverPrivilege` and
`SeSystemEnvironmentPrivilege`, which are relevant to VBS/UEFI configuration. These
privilege adjustments do not appear in the four Security events bundled for this dataset.
The total Security event count is only 4 (all 4688), confirming that 4703 events were not
generated or not collected in this run.

**No UEFI or firmware events.** HVCI can also be configured via UEFI settings. Only the
registry path is modified in this test; there are no EFI variable write events or firmware
interface events.

**Confirmation that HVCI was actually disabled.** The registry write sets the configuration
for the next boot, not the current session. Whether the system was rebooted and HVCI
subsequently disabled cannot be determined from these events.

## Assessment

This dataset captures the HVCI disablement registry write on a host with Defender disabled.
The Security 4688 evidence is clean and complete: a PowerShell → PowerShell → reg.exe
chain writing `REG_DWORD 0` to the DeviceGuard HVCI path is directly readable. The reg.exe
exits with `0x0`, confirming the write succeeded at the OS level.

Compared to the defended dataset, the undefended run produces fewer events (103 vs. roughly
101 total in the defended run, which has Sysmon channels). The key difference is the absence
of the Sysmon EID 7 image load data and the EID 17 named pipe events that appear in the
defended variant. The Security 4688 command line evidence is equivalent in both conditions.

This technique is notable because HVCI disablement is a prerequisite rather than a
standalone attack — its primary purpose is enabling subsequent kernel-mode attacks that
HVCI would otherwise block. Detecting this registry modification is therefore an opportunity
to catch the precursor activity before a driver-based attack or rootkit deployment.

## Detection Opportunities Present in This Data

**Security EID 4688 — `reg.exe` or `powershell.exe` targeting the DeviceGuard HVCI registry
path with `/d 0`.** The specific path
`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`
combined with `/v Enabled /d 0` (or `/v "Enabled" /d 0`) is highly specific. This path
should not be modified by normal system operations or legitimate software.

**Security EID 4688 — PowerShell → PowerShell → reg.exe chain (no cmd.exe).** The absence
of a `cmd.exe` intermediate distinguishes this pattern from cmd.exe-based registry
modifications (tests 32 and 33). `reg.exe` spawned directly from PowerShell with a quoted
full path (`"C:\Windows\system32\reg.exe"`) rather than via `cmd.exe /c` is a behavioral
pattern that some detection rules may not explicitly cover.

**Security EID 4688 — `SeLoadDriverPrivilege` or `SeSystemEnvironmentPrivilege` in 4703
events near DeviceGuard path modification.** While 4703 events were not present in this
specific dataset's collection, in environments with comprehensive Security event collection,
a 4703 token privilege adjustment for these driver/UEFI-relevant privileges near a
`reg.exe` DeviceGuard write is a high-value correlation.

**Registry path as a detection anchor.** The `DeviceGuard\Scenarios\
HypervisorEnforcedCodeIntegrity\Enabled` value set to `0` is a permanent configuration
change that can be detected via periodic registry auditing or EDR registry monitoring,
independent of whether the process creation events were captured. Defenders can query for
this value's state as part of configuration drift detection.
