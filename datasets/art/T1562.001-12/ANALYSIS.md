# T1562.001-12: Disable or Modify Tools — Uninstall Sysmon

## Technique Context

T1562.001 (Impair Defenses: Disable or Modify Tools) is among the most critical techniques to detect. If an attacker successfully disables security monitoring, all subsequent activity becomes invisible — making this a gateway technique that amplifies the impact of everything that follows.

This test targets Sysmon specifically, using `sysmon -u` to trigger the uninstall procedure. Sysmon is a widely deployed endpoint monitoring tool that provides deep visibility into process creation, network connections, registry modifications, file creation, and other OS-level activity. Disabling it is a priority objective for sophisticated attackers who have gained SYSTEM-level access.

This technique has an inherent **observer problem** that makes it forensically fascinating: if Sysmon is successfully uninstalled, can it log its own removal? The answer depends on a race condition between the uninstall command's execution and Sysmon's event processing pipeline. The kernel minifilter driver (SysmonDrv) processes events asynchronously, so there is a narrow window where Sysmon can capture the process creation of its own uninstaller before the driver is detached.

The detection community watches for:

- **Process creation containing `sysmon -u`, `sysmon64 -u`, or `sysmon.exe -uninstall`** — the direct uninstall command
- **Service stop events** (System EID 7036/7045) for the Sysmon64 service
- **Driver unload events** — Sysmon EID 255 (DriverCommunication error), or `fltmc unload SysmonDrv`
- **Telemetry gaps** — the sudden absence of Sysmon events across an environment is itself a signal that can be detected by a SIEM correlation rule

## What This Dataset Contains

Both **Sysmon EID 1** and **Security 4688** captured the technique command:

```
cmd.exe /c sysmon -u
```

The complete process chain is visible: `powershell.exe (SYSTEM) → cmd.exe /c sysmon -u → (implicit: sysmon.exe would be invoked)`. SHA256 hashes are captured for all processes in the chain.

The **Security 4689** event for cmd.exe reveals a critical detail: the process **exited with status 0x1 (failure)**. The `sysmon -u` command did not succeed. This means Sysmon was never actually uninstalled, and the driver remained loaded throughout the test.

**Security 4703** shows the parent PowerShell process enabling `SeLoadDriverPrivilege` — the specific Windows privilege required for loading and unloading kernel drivers and managing services. Seeing this privilege enabled on a PowerShell process is inherently suspicious and represents an independent detection opportunity, even before examining what the process does with that privilege.

Sysmon continued logging events after the uninstall attempt, including FileCreate events at t+5.6 seconds, confirming the service was never interrupted.

## What This Dataset Does Not Contain

**The uninstall attempt failed**, so none of the "successful defense impairment" telemetry is present:

- No System EID 7036 (service stopped) or 7045 (service state change) for Sysmon64
- No Sysmon EID 255 (driver communication error) that would indicate the driver detaching
- No telemetry gap — Sysmon kept logging normally

**The root cause of the failure** is that the ART test calls `sysmon -u`, but on this Windows 11 system, the Sysmon binary is installed as `Sysmon64.exe` and is not on the system PATH. The command simply failed with "not recognized" or "not found." This is a test quality issue in ART — the test doesn't adapt to the system's actual Sysmon installation path. A real attacker would enumerate the Sysmon binary location first (checking `C:\Windows\Sysmon64.exe`, `C:\Windows\Sysmon.exe`, or querying the service binary path via `sc qc Sysmon64`).

**The PowerShell channel has no technique content.** All 32 EID 4104 events are internal `Set-StrictMode` scriptblock templates, and the 2 EID 4103 events are `Set-ExecutionPolicy Bypass` test framework setup. The technique was dispatched via `cmd.exe`, not executed natively in PowerShell.

**No System channel events.** The event pipeline for this dataset only ingested Sysmon, Security, and PowerShell channels. System channel events (7036, 7045) would be relevant for service-level detection of Sysmon removal but are not present regardless of the test outcome.

## Assessment

This dataset documents a **failed defense evasion attempt** due to a binary path resolution issue. The `sysmon -u` command line is visible in both Sysmon and Security process creation logs, which validates command-line-based detection rules — and detecting failed attempts is valuable, since they indicate an attacker probing for security tool removal options.

The more forensically interesting question — what does it look like when an attacker successfully removes Sysmon — is not answered here. Specifically: does Sysmon log its own EID 1 for the uninstall process before the driver unloads? How many events does the pipeline capture between the uninstall command and the driver detach? What does the telemetry gap look like from a SIEM's perspective? These questions are important for SOC playbook development, and answering them would require a test where the uninstall actually succeeds (e.g., `cmd.exe /c "C:\Windows\Sysmon64.exe" -u force`).

For comparison, T1562.001-11 in this collection executes `fltmc.exe unload SysmonDrv`, which directly detaches the kernel minifilter driver — a more surgical approach that bypasses the service manager entirely. That test's dataset and this one represent two different attacker approaches to the same goal, and a robust detection strategy should cover both.

## Detection Opportunities Present in This Data

1. **Sysmon uninstall command** (Sysmon EID 1 / Security 4688): Any process creation where `CommandLine` contains `sysmon` and (`-u` or `-uninstall` or `unload`). This should be a high-priority alert in any environment.

2. **SeLoadDriverPrivilege enablement on PowerShell** (Security 4703): This privilege is required for kernel driver and service manipulation. PowerShell processes enabling it should trigger investigation, especially when combined with other indicators.

3. **Failed execution as signal** (Security 4689): A process exit code of 0x1 on a command that attempted to uninstall a security tool indicates the attacker tried and failed. This is an early warning — they may try a different approach next.

4. **Temporal pattern**: SYSTEM-level process running `Set-ExecutionPolicy Bypass` followed by an attempt to uninstall a security monitoring tool. This sequence of preparation-then-disable is characteristic of automated attack tooling.

## Environment Note

This test was executed on a Windows 11 Enterprise workstation (ACME-WS02) with Sysmon installed as `Sysmon64.exe` with the SysmonDrv kernel minifilter driver. Windows Defender was active. The test ran as NT AUTHORITY\SYSTEM via the QEMU guest agent.
