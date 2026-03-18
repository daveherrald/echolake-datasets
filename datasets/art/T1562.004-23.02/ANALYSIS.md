# T1562.004-23: Disable or Modify System Firewall — ESXi - Disable Firewall via Esxcli

## Technique Context

T1562.004 (Disable or Modify System Firewall) covers firewall disablement across platforms. This test targets VMware ESXi hypervisor infrastructure rather than the Windows host itself. It attempts to disable the ESXi firewall by SSHing into a remote ESXi host using `plink.exe` (PuTTY's command-line SSH client) and issuing:

```
esxcli network firewall set --enabled false
```

Disabling the ESXi firewall removes network access controls protecting virtual machines and management interfaces, enabling lateral movement between VMs and external access to management APIs. This technique has been used by ransomware groups (ALPHV, ESXiArgs) targeting VMware virtualization infrastructure to prepare for VM-level encryption. The test is executed from a Windows workstation — the attacker's foothold — using `plink.exe` pre-staged by the ART test framework at `C:\AtomicRedTeam\ExternalPayloads\plink.exe`. The target ESXi host is a placeholder (`atomic.local`) that does not resolve in this environment, so no actual firewall change occurs.

## What This Dataset Contains

The dataset spans roughly five seconds and captures 109 events across PowerShell (97), Security (11), and Application (1) channels.

**Security (EID 4688):** Four process creation events. PowerShell (parent) spawns `whoami.exe` (test framework identity check), then spawns `cmd.exe` with the full plink invocation:

```
"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh atomic.local -l root -pw n/a -m C:\AtomicRedTeam\atomics\..\atomics\T1562.004\src\esxi_disable_firewall.txt
```

The command-line field captures the target host (`atomic.local`), SSH username (`root`), the placeholder password (`n/a`), and the path to the remote command file (`esxi_disable_firewall.txt`). The cleanup invocation (EID 4688) shows the corresponding cleanup command using `esxi_enable_firewall.txt`.

A token right adjustment (EID 4703) is present for `powershell.exe`, showing a large set of enabled SYSTEM privileges including SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeDebugPrivilege.

**Application (EID 15):** "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." — Windows Security Center background update, unrelated to the technique.

**PowerShell (EID 4103 + 4104):** 97 events. Two EID 4103 events record `Set-ExecutionPolicy Bypass -Scope Process -Force` and a related test framework cmdlet. EID 4104 events include `Set-ExecutionPolicy Bypass -Scope Process -Force`, `$ErrorActionPreference = 'Continue'`, and the cleanup invocation `Invoke-AtomicTest T1562.004 -TestNumbers 23 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

**No plink.exe process creation event.** `plink.exe` is launched by `cmd.exe` but does not appear as an EID 4688 event. The Security process creation audit policy captures `cmd.exe` and `whoami.exe` but not `plink.exe` — likely because `plink.exe` is not a known system binary and enhanced auditing only logs process creations for executables matching specific criteria in this environment's audit configuration. In the defended variant, Sysmon EID 1 also did not capture `plink.exe` because the sysmon-modular include rules do not match it by name or path pattern.

**No Sysmon events.** The defended variant captured 26 Sysmon events including EID 1 (process creates for `whoami.exe`, `cmd.exe`, and PowerShell), EID 7 (image loads), EID 10 (process access), EID 11 (file creates), and EID 17 (named pipe). None of that is present here.

**No network connection to the ESXi host.** The hostname `atomic.local` does not resolve in this environment, so `plink.exe` cannot establish an SSH connection. No Sysmon EID 3 (network connection) or EID 22 (DNS query) events appear for `atomic.local`. In a real intrusion with a valid target, you would expect to see TCP port 22 connection attempts.

**No ESXi-side telemetry.** Even if the connection had succeeded, ESXi firewall state changes would generate logs on the ESXi host itself (ESXi syslog, vCenter events), not on the Windows workstation. This dataset captures only the Windows-side execution context.

**No payload content.** The `esxi_disable_firewall.txt` file is referenced by path but its contents (`esxcli network firewall set --enabled false`) are not logged by any collected Windows source.

## Assessment

The technique attempted to connect to a non-existent ESXi host and failed at the network level. The Windows-side execution chain completed normally: `cmd.exe` was created, `plink.exe` was launched (not captured in EID 4688), the connection attempt failed, and the process exited. The core forensic evidence is the Security EID 4688 for `cmd.exe`, which contains the full `plink.exe` invocation including the target host, credentials, and command file path.

In a real attack scenario, the credentials would be actual ESXi credentials, the target would be a reachable host IP, and the command would successfully disable the ESXi firewall. The detection opportunity is the same in both the test and real scenarios — the `cmd.exe` command-line field captures the complete attack intent.

Compared to the defended variant (26 Sysmon + 10 Security + 34 PowerShell = 70 total), the undefended run produced 97 PowerShell + 11 Security + 1 Application events (109 total). The absence of Sysmon is the primary difference; the Security channel is slightly richer in the undefended run due to additional process exit and token adjustment events.

## Detection Opportunities Present in This Data

- **Security EID 4688 (cmd.exe command line):** The `plink.exe` invocation with `-ssh`, `-l root`, `-pw`, and `-m` flags targeting a non-Windows host is a recognizable pattern for cross-platform lateral movement from a Windows workstation. Any `plink.exe` invocation targeting ESXi management hosts warrants immediate investigation.
- **Security EID 4688 (command file path):** The reference to `esxi_disable_firewall.txt` or any file with "esxi" and "firewall" in the name is a high-specificity indicator.
- **Plaintext credentials:** The `-pw n/a` field in the command line (placeholder here; would be real credentials in an attack) demonstrates that `plink.exe` invocations may expose credentials in process creation logs.
- **PowerShell EID 4104:** The cleanup block contains `Invoke-AtomicTest T1562.004 -TestNumbers 23` — useful for identifying ART test execution but not specific to real-world attacks.
- **Process ancestry:** `cmd.exe` spawned by `powershell.exe` under SYSTEM context, executing a non-standard binary from `C:\AtomicRedTeam\ExternalPayloads\` (or analogous staging paths in real attacks), is worth alerting on when the binary is `plink.exe` or other known lateral movement tools.
