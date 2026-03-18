# T1560.001-10: ESXi — Remove Syslog Remote IP

## Technique Context

T1560.001 covers Archive via Utility, but this test is notably mislabeled by its MITRE technique assignment. The actual behavior is an adversary connecting to a VMware ESXi hypervisor via SSH (using PuTTY's `plink.exe`) to retrieve and then clear the syslog remote forwarding configuration. The operational purpose is defense evasion — removing the remote syslog destination prevents ESXi logs from being forwarded to a SIEM, blinding defenders to hypervisor-level activity. This technique appears in ransomware intrusions that target VMware infrastructure, where attackers disable logging before deploying the encryptor. The MITRE T1560.001 label likely reflects the use of archiving utilities in the ART framework rather than the true technique purpose.

## What This Dataset Contains

The dataset spans 5 seconds (01:20:15–01:20:20 UTC) across 26 Sysmon events, 10 Security events, and 53 PowerShell events.

The ART test framework executes a complex PowerShell script block captured in its entirety by Security 4688 and PowerShell 4104 script block logging:

```
"powershell.exe" & {
C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh atomic.local -l root -pw n/a -m C:\...\esxi_get_loghost.txt | findstr /r "[0-9]*\.[0-9]*\.[0-9]*\." > c:\temp\loghost.txt
C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh atomic.local -l root -pw n/a -m C:\...\esxi_remove_loghost.txt
# [...IP extraction and output to c:\temp\loghost_ip.txt...]
}
```

The script uses `plink.exe` (PuTTY command-line SSH client) to connect to `atomic.local` with hard-coded root credentials (`-pw n/a`). It retrieves the current syslog loghost configuration, extracts the IP address, and then removes the syslog forwarding destination. The full script block is logged in PowerShell 4104.

Sysmon EID 1 captures the child `powershell.exe` spawned to execute the script, tagged `technique_id=T1083` (File and Directory Discovery) from the `-Recurse` pattern in the sysmon-modular rules. The test framework `whoami.exe` preflight appears in Sysmon EID 1 and Security 4688. Two `\PSHost.*` pipes appear in Sysmon EID 17.

The `cmd.exe` exit status is not present — this test uses a direct `powershell.exe` invocation rather than a `cmd.exe` wrapper.

## What This Dataset Does Not Contain (and Why)

No `plink.exe` process creation appears in Sysmon EID 1. The Sysmon ProcessCreate include filter does not have a rule matching `plink.exe`, so no EID 1 was generated for the SSH client. Security 4688 does not show `plink.exe` either, suggesting the SSH client was either blocked by Defender or the process creation was not captured because the binary was absent.

No successful SSH connection to `atomic.local` occurred — no such host exists in the test environment. The script would fail silently when `plink.exe` cannot connect, and no output files (`c:\temp\loghost.txt`, `c:\temp\loghost_ip.txt`) would be created. No file creation events for these paths appear in Sysmon EID 11.

No ESXi syslog configuration changes are captured because no real ESXi infrastructure exists in the test environment. The target `atomic.local` is a placeholder hostname used across many ART tests for infrastructure-dependent techniques.

## Assessment

This dataset captures the full intent and command structure of an ESXi syslog disabling technique through the PowerShell script block log — the highest-fidelity evidence available — even though execution failed due to the absence of the target infrastructure. The `plink.exe` SSH invocation with root credentials and the specific ESXi CLI commands (`esxcli system syslog config set --loghost=`) are fully preserved in the PowerShell 4104 events. This dataset is particularly useful for training on the use of `plink.exe` as an SSH execution proxy and for detecting ESXi management commands issued from Windows workstations.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: Complete script block text including `plink.exe -ssh atomic.local -l root -pw n/a`; hard-coded root credentials in a PowerShell script block is a critical finding regardless of success.
- **PowerShell 4104**: `esxcli system syslog config set --loghost=` command string embedded in the script; ESXi management commands issued from a Windows workstation are highly anomalous.
- **Security 4688**: `powershell.exe` with inline script block containing `plink.exe` SSH client invocation under SYSTEM context; `plink.exe` used programmatically from PowerShell warrants investigation.
- **Sysmon EID 1**: Child `powershell.exe` spawned from SYSTEM-context `powershell.exe` for non-interactive script execution; the `T1083` tag from the directory traversal pattern fires even on non-archiving activity.
- **File paths**: References to `c:\temp\loghost.txt` and `c:\temp\loghost_ip.txt` as output targets; monitoring writes to `C:\Temp\` from PowerShell for IP-related content names is a weak but useful signal.
- **findstr usage**: `findstr /r "[0-9]*\.[0-9]*\.[0-9]*\."` in a PowerShell pipeline to extract IP addresses from tool output; this pattern is common in living-off-the-land IP harvesting scripts.
