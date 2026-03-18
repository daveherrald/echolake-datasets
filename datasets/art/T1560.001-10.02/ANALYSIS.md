# T1560.001-10: Archive via Utility — ESXi Remove Syslog Remote IP

## Technique Context

Despite its MITRE T1560.001 (Archive via Utility) label, this test's actual behavior is a defense evasion operation against VMware ESXi hypervisor infrastructure. The test uses `plink.exe` (PuTTY's command-line SSH client) to connect to an ESXi host and remove its remote syslog forwarding configuration. Removing the syslog destination blinds a SIEM to hypervisor-level activity — process creation, VM configuration changes, datastore access — that would otherwise be forwarded to a centralized logging platform.

This technique appears in intrusions targeting virtualized environments, particularly ransomware operations that target ESXi before deploying encryptors against VM disk files. Disabling remote logging is typically performed early in the attack chain to prevent the SIEM from alerting on the encryptor's activity.

The T1560.001 mapping likely reflects the ART framework's categorization of this test alongside other archive/collection utilities, but the operational purpose is closer to T1562 (Impair Defenses).

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:33:43–17:33:46 UTC) and contains 114 PowerShell events, 3 Security events, and 26 Sysmon events.

The full attack command is captured in Security EID 4688:
```
"powershell.exe" & {# Extract line with IP address from the syslog configuration output
C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh atomic.local -l root -pw n/a -m C:\AtomicRedTeam\atomics\..\atomics\T1560.001\src\esxi_get_loghost.txt | findstr /r "[0-9]*\.[0-9]*\.[0-9]*\." &...}
```

The command invokes `plink.exe` against `atomic.local` with username `root` and password `n/a`, using a command file (`esxi_get_loghost.txt`) to retrieve the current syslog host configuration, then pipes the output through `findstr` to extract the IP address. A second `plink.exe` invocation using `esxi_remove_loghost.txt` would then remove the syslog forwarding configuration. The credential `-pw n/a` is a placeholder from the ART default parameters.

Sysmon EID 1 captures 3 process creation events:
- `whoami.exe` (pre-execution check) with parent `powershell.exe`
- The attack `powershell.exe` with the full `plink.exe` command block in its command line, tagged `RuleName: technique_id=T1059.001,technique_name=PowerShell`
- A second `whoami.exe` (post-execution check)

Sysmon EID 7 records 17 ImageLoad events for the two PowerShell instances. Sysmon EID 10 records 3 ProcessAccess events. Sysmon EID 17 records 2 pipe creation events. Sysmon EID 11 records 1 FileCreate event (PowerShell startup profile data).

The PowerShell events are 113 EID 4104 script block logging events and 1 EID 4103 module logging event, containing ART test framework boilerplate plus the `Set-ExecutionPolicy Bypass` and `$ErrorActionPreference = 'Continue'` preamble, and the cleanup scriptblock `Invoke-AtomicTest T1560.001 -TestNumbers 10 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

No `plink.exe` process creation appears in Sysmon EID 1 or Security 4688. The `plink.exe` binary resides at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe` and was present in the ART environment, but the Sysmon ProcessCreate include-mode filter does not have a rule matching `plink.exe` by name. Security 4688 process creation auditing also did not capture `plink.exe` — it may not have been in scope, or the process failed to launch before the collection window.

No network connection events appear. There is no Sysmon EID 3 (NetworkConnect) for a connection to `atomic.local`. No such host exists in the `acme.local` domain, so `plink.exe` would have received a DNS resolution failure and exited immediately without establishing a TCP connection. No DNS query event (Sysmon EID 22) for `atomic.local` is present.

No output files (`c:\temp\loghost.txt`, `c:\temp\loghost_ip.txt`) were created. Without a successful SSH connection, `plink.exe` produces no output and the `findstr` pipeline receives empty input. No Sysmon EID 11 for these paths appears.

No ESXi syslog modification occurred. This test requires a reachable ESXi host at `atomic.local` with root credentials. The technique failed at the network layer.

Compared to the defended variant (26 Sysmon, 10 Security, 53 PowerShell), the structure is nearly identical — this test behaves the same with or without Defender because the failure is due to a missing network target, not a security product block.

## Assessment

This dataset documents the command-line evidence of an attempted ESXi syslog disabling operation. While the technique did not execute against a real target, the command line preserved in Security EID 4688 and Sysmon EID 1 is the primary artifact: the `plink.exe` invocation with hardcoded credentials, SSH command files pointing to `esxi_get_loghost.txt` and `esxi_remove_loghost.txt`, and the `findstr /r` IP extraction pattern.

The dataset illustrates a reconnaissance-to-action sequence that an attacker would use against actual VMware infrastructure. The command structure is forensically specific: `plink.exe -ssh <host> -l root -pw <password> -m <command_file>` is a documented pattern in VMware-targeting intrusions.

The fact that this is categorized as T1560.001 while its operational behavior maps more cleanly to T1562 (Impair Defenses) is worth noting for anyone building detection coverage — the MITRE label alone is insufficient for coverage decisions.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 command line**: A `powershell.exe` process with a command line containing `plink.exe -ssh` and `-l root` is a high-specificity indicator. Root-credential SSH via PuTTY's command-line client is not a normal enterprise activity on a Windows workstation, regardless of whether the target is reachable.

**`plink.exe` path**: The binary resides under `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` — in a real intrusion, `plink.exe` is typically staged in a temporary or attacker-controlled directory. The path itself is an indicator worth monitoring.

**Hardcoded credentials in command line**: `-pw n/a` appears in the command line captured by Security EID 4688. In real intrusions, this field contains the actual ESXi root password. Any process creation event containing `-l root -pw` in the command line should be treated as high priority.

**SSH command file references**: The `-m C:\AtomicRedTeam\atomics\..\atomics\T1560.001\src\esxi_get_loghost.txt` parameter shows a file-based SSH command pattern. Detecting `plink.exe -m <file>` invocations can catch this pattern even when the credentials differ.
