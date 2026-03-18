# T1562.004-23: ESXi — Disable Firewall via Esxcli

## Technique Context

T1562.004 covers firewall disablement. Test 23 targets VMware ESXi infrastructure rather than
the Windows host — it attempts to disable the ESXi firewall by SSHing into a remote ESXi host
using `plink.exe` (PuTTY's command-line SSH client) and running `esxcli network firewall set
--enabled false`. The test is designed for environments where an attacker has lateral movement
capability to VMware hypervisors, a technique associated with ransomware groups targeting
virtualization infrastructure.

The test is executed from a Windows workstation. The plink binary is pre-staged by the ART
test framework at `C:\AtomicRedTeam\ExternalPayloads\plink.exe`. The target is a dummy ESXi address
(`atomic.local`) with placeholder credentials.

## What This Dataset Contains

**Sysmon (26 events):** Sysmon ID 1 captures:

- `whoami.exe` (RuleName: T1033)
- `cmd.exe /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh atomic.local -l root -pw n/a -m C:\AtomicRedTeam\atomics\..\atomics\T1562.004\src\esxi_disable_firewall.txt` (RuleName: T1059.003)

The plink.exe process itself does not appear in Sysmon 1. Sysmon 7 (image loads), 10 (process
access), 11 (file create), and 17 (named pipe) events document the PowerShell test framework and cmd.exe.

**Security (10 events):** 4688/4689 for whoami and cmd.exe. The 4688 for cmd.exe contains the
full plink invocation in the process command line, including the target host (`atomic.local`),
username (`root`), and the reference to the ESXi disable firewall command file. Token adjustment
(4703).

**PowerShell (34 events):** ART test framework boilerplate only — `Set-ExecutionPolicy Bypass` and
error-handling fragments. No technique-specific cmdlets.

## What This Dataset Does Not Contain (and Why)

**No plink.exe in Sysmon 1.** Plink is not a known LOLBin and does not match the sysmon-modular
include rules for ProcessCreate. Its creation and termination appear in Security 4688/4689 (not
shown explicitly here — the 4688 for cmd.exe is the primary capture). This is a genuine Sysmon
coverage gap for non-standard executables.

**No network connection events.** The `atomic.local` hostname does not resolve in this
environment, so plink cannot establish an SSH connection. No Sysmon 3 (network connection)
events appear; the connection attempt fails silently.

**No ESXi-side telemetry.** The ESXi firewall change (if it succeeded) would generate logs on
the hypervisor, not on the Windows workstation. This dataset captures only the Windows-side
initiation.

**No file content capture.** The `esxi_disable_firewall.txt` payload is referenced by path but
its contents (`esxcli network firewall set --enabled false`) are not logged by any collected
source. Neither Sysmon nor Security log file reads.

**No Defender block.** Unlike some other tests where Defender blocks execution (exit code
0xC0000022), plink is not flagged here — it fails to connect but is not blocked by AV.

## Assessment

The test attempted but did not complete — plink cannot reach `atomic.local` in this isolated
domain environment. What remains is the launch telemetry: the cmd.exe wrapper with the full
plink command line. This is still detection-relevant, as defenders can identify the initiation
attempt even without a successful SSH connection. The dataset honestly reflects the Windows-side
visibility for this cross-platform technique.

## Detection Opportunities Present in This Data

- **Sysmon 1 / Security 4688:** cmd.exe invoking `plink.exe -ssh` with `-l root` targeting any
  host — SSH from a Windows workstation as root to an external host is anomalous.
- **Security 4688:** The cmd.exe event contains the full plink command line including hostname,
  username, and the `-m` (command file) parameter, providing actionable IOC fields.
- **File path:** `C:\AtomicRedTeam\ExternalPayloads\plink.exe` is ART-specific, but the
  detection principle applies to any plink.exe outside standard paths being used for SSH
  lateral movement.
- **Command file reference:** The `-m` parameter pointing to an `esxi_disable_firewall.txt` or
  similar ESXi command file from a Windows temp/staging directory is a strong behavioral
  indicator of ESXi-targeting lateral movement.
- **Cross-platform detection gap:** The actual firewall disable on ESXi, if successful, would
  not appear in Windows telemetry at all. Defenders must also monitor ESXi audit logs and
  syslog for `esxcli network firewall` commands from unexpected sources.
