# T1562.004-25: Disable or Modify System Firewall — ESXi - Set Firewall to PASS Traffic

## Technique Context

T1562.004 (Disable or Modify System Firewall) covers firewall modification across platforms. This test targets VMware ESXi hypervisors by setting the default firewall action to pass (allow all traffic) using:

```
esxcli network firewall set --default-action true
```

Where `--default-action true` means "pass all traffic by default." Unlike disabling the firewall entirely (`--enabled false`, covered by T1562.004-23), setting the default action to pass leaves the firewall technically enabled while making it permissive — potentially evading detection systems that alert only on firewall service disablement. Adversaries targeting ESXi infrastructure (documented in ALPHV/BlackCat and ESXiArgs ransomware campaigns) use this approach to enable lateral movement between VMs and external C2 communication without completely disabling the firewall.

The test executes from a Windows workstation using `plink.exe` (PuTTY command-line SSH client) with a pipe from `echo ""` to provide stdin to the non-interactive SSH session. The target ESXi host (`atomic.local`) does not exist in this environment, so no actual firewall modification occurs.

## What This Dataset Contains

The dataset spans roughly five seconds and captures 125 events across PowerShell (107), Security (17), and Application (1) channels.

**Security (EID 4688):** Six process creation events. PowerShell (parent) spawns `whoami.exe` (test framework identity check), then spawns `cmd.exe` with the full attack command:

```
"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" -batch "atomic.local" -ssh -l root -pw "password" "esxcli network firewall set --default-action true"
```

`cmd.exe` (PID 0x...) then spawns a second `cmd.exe` as the shell managing the pipe's left side:

```
C:\Windows\system32\cmd.exe  /S /D /c" echo "" "
```

This second `cmd.exe` invocation is the pipe producer — it executes `echo ""` to provide the empty stdin that allows `plink.exe` to run non-interactively (`-batch` mode). The cleanup `cmd.exe` invocation is also captured:

```
"cmd.exe" /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" -batch "atomic.local" -ssh -l root -pw "password" "esxcli network firewall set --default-action false"
```

Note that the cleanup command uses `--default-action false` (restore drop as default), which confirms this is the expected ART cleanup reversing the attack.

All processes run as `NT AUTHORITY\SYSTEM` (S-1-5-18, ACME\ACME-WS06$) with System integrity label.

A token right adjustment (EID 4703) for `powershell.exe` is present, showing the SYSTEM privilege set including SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege, and others.

**Security (EID 4689):** Ten process exit events for the processes above.

**Application (EID 15):** "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." — Windows Security Center background activity, unrelated to the technique.

**PowerShell (EID 4103 + 4104):** 107 events. Three EID 4103 events record test framework-level cmdlets including `Set-ExecutionPolicy Bypass -Scope Process -Force`. EID 4104 events are predominantly ART test framework boilerplate.

## What This Dataset Does Not Contain

**No `plink.exe` process creation event.** Despite `plink.exe` being launched by `cmd.exe`, no EID 4688 for `plink.exe` itself appears. The Security audit policy does not capture it; in the defended variant, Sysmon EID 1 also did not capture `plink.exe` because it is not matched by the sysmon-modular include rules. This is a systematic gap for non-standard executable monitoring that applies to both defended and undefended configurations.

**No Sysmon events.** The defended variant captured 27 Sysmon events including EID 1 (process creates), EID 7 (image loads), EID 10 (process access), EID 11 (file creates), and EID 17 (named pipe). None is present here.

**No network connection to the ESXi host.** `atomic.local` does not resolve, so `plink.exe` cannot establish an SSH connection. No Sysmon EID 3 or EID 22 events appear for the connection attempt. In a real attack against a reachable target, TCP port 22 connection events would be present.

**No ESXi-side telemetry.** If the connection had succeeded, ESXi and vCenter would record the firewall change in ESXi syslog and vSphere event history. Those are out of scope for this Windows-side dataset.

## Assessment

The technique attempted to set the ESXi firewall default action via SSH from the Windows workstation. The connection failed at the network level because `atomic.local` does not exist, but the complete execution intent is documented in the Security EID 4688 events.

The `echo "" | plink.exe -batch` pattern is a specific technique for non-interactive SSH command execution from Windows — the pipe provides stdin so `plink.exe` does not hang waiting for a password prompt when `-batch` mode is insufficient alone. This pattern, combined with the `-l root` credential and an `esxcli` command, is a recognizable fingerprint for ESXi-targeted lateral movement from Windows hosts.

Compared to the defended variant (27 Sysmon + 14 Security + 34 PowerShell = 75 total), the undefended run produced 107 PowerShell + 17 Security + 1 Application events (125 total). The Security channel in the undefended run is richer (17 vs. 14 events) due to additional process exit records. The primary difference remains the absent Sysmon data.

## Detection Opportunities Present in This Data

- **Security EID 4688 (cmd.exe command line):** The string `esxcli network firewall set --default-action true` in the `cmd.exe` command line is a high-specificity indicator of ESXi firewall modification from a Windows host.
- **Security EID 4688 (plink.exe pattern):** The `echo "" | plink.exe -batch ... -l root -pw "password" "esxcli ..."` invocation pattern is recognizable regardless of the specific ESXi command being issued. Any `plink.exe` invocation with ESXi-related commands and `-l root` warrants investigation.
- **Plaintext credentials in process command line:** The `-pw "password"` field is visible in EID 4688 — in real attacks this would contain actual credentials. Process creation logging is an important source for credential exposure in lateral movement scenarios.
- **Second-level cmd.exe:** The `cmd.exe /S /D /c" echo "" "` subprocess confirms the pipe construct is in use — a minor anomaly in `cmd.exe` ancestry that can help distinguish this pattern from simpler command executions.
- **Cleanup command as confirmation:** The cleanup `cmd.exe` invocation with `--default-action false` is captured, which would be present in an actual attack if the attacker or post-exploitation framework cleans up.
