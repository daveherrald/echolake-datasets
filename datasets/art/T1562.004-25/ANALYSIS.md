# T1562.004-25: Disable or Modify System Firewall — ESXi - Set Firewall to PASS Traffic

## Technique Context

T1562.004 (Disable or Modify System Firewall) encompasses firewall modification across platforms.
This test targets VMware ESXi hypervisors using the `esxcli network firewall set --default-action
true` command, which sets the default firewall action to pass (allow all) rather than drop.
Adversaries targeting virtualization infrastructure — including ransomware groups like ALPHV and
ESXiArgs — disable ESXi firewall controls to enable lateral movement between VMs and to
facilitate data exfiltration. The test runs from a Windows host, using `plink.exe` (PuTTY command
line SSH client) to deliver the command to the ESXi host over SSH.

## What This Dataset Contains

The test ran:
```
cmd.exe /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" -batch "atomic.local"
  -ssh -l root -pw "password" "esxcli network firewall set --default-action true"
```
under NT AUTHORITY\SYSTEM. There was no reachable ESXi host at `atomic.local`, so the command
was dispatched but the SSH session failed.

**Sysmon EID 1 — process creation (27 events, 3 process-create):**
- `cmd.exe /c echo "" | plink.exe -batch "atomic.local" -ssh -l root -pw "password" "esxcli network firewall set --default-action true"` (parent: powershell.exe)
- Two `cmd.exe` instances (the outer wrapper and the `echo ""` child)
- `whoami.exe` (ART test framework pre-check)
- plink.exe itself does not appear as a Sysmon EID 1 event — it is not matched by the sysmon-modular include rules, though it was launched

**Security EID 4688 (14 events):** cmd.exe, echo subprocess (another cmd.exe), whoami.exe.
Token Elevation Type 1 under SYSTEM.

**PowerShell EID 4104 (34 events):** The ART test framework script block logs contain only boilerplate.
The actual command was issued entirely in cmd.exe; no test-specific content appears in the
PowerShell log.

## What This Dataset Does Not Contain (and Why)

**No plink.exe Sysmon EID 1:** The Sysmon include-mode ProcessCreate configuration does not
match plink.exe by name or path, so plink.exe process creation was not captured in Sysmon. It
does appear in Security EID 4688 (process creation audit) — but even the 4688 events in this
dataset do not show plink.exe, suggesting plink.exe may have been captured outside the selected
event window or filtered. The cmd.exe process that launches it is captured.

**No network connection to ESXi host:** plink.exe attempted to connect to `atomic.local:22` but
the target does not exist. There are no Sysmon EID 3 events showing an outbound SSH connection.
The ESXi firewall change was not executed.

**No esxcli output or SSH session events:** ESXi syslog and vSphere events would be present on
the target if the connection had succeeded, but are out of scope for this Windows-side dataset.

**No Sysmon EID 13 (registry) or firewall-related changes:** No Windows firewall rules were
modified — this test is about the ESXi firewall, not the Windows firewall.

**Windows Defender did not block plink.exe** in this instance (the process ran), though the SSH
connection itself failed.

## Assessment

This dataset is primarily useful as a Windows-side view of an attacker using SSH tooling
(plink.exe) to target hypervisor infrastructure. The most valuable artifact is the cmd.exe
command line in Sysmon EID 1, which contains the complete plink.exe invocation including
credentials (`-pw "password"`) and the target command (`esxcli network firewall set
--default-action true`). Credentials passed on the command line are fully visible in process
telemetry. The test did not succeed (no ESXi target), so this dataset represents attempt
telemetry rather than success telemetry.

The PowerShell log contributes no detection value for this test.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `cmd.exe` with a command line containing `plink.exe` and `esxcli` — indicates Windows-to-ESXi lateral movement attempt
- **Sysmon EID 1:** `plink.exe` (or any SSH client) spawned from PowerShell or cmd.exe with `-batch`, `-ssh`, `-l root`, and `-pw` arguments — hardcoded credentials are a strong indicator
- **Sysmon EID 1:** Any process invocation referencing `esxcli network firewall set --default-action` on the command line
- **Sysmon EID 3 (if plink.exe is captured):** Outbound TCP/22 connection to an IP in the RFC1918 range from a workstation — unusual unless part of authorized admin workflow
- **Credential exposure:** `-pw "password"` on the command line is visible in both Sysmon EID 1 and Security EID 4688 with command-line auditing enabled — a LOLB for credential harvesting by defenders
