# T1016-7: System Network Configuration Discovery — Qakbot Recon

## Technique Context

Qakbot (also known as QBot) is a sophisticated banking trojan and post-compromise toolkit that has been used extensively by ransomware affiliates for initial access and lateral movement preparation. One of Qakbot's early post-compromise behaviors is a systematic network and user reconnaissance routine executed via a batch script. This ART test (`qakbot.bat`) replicates that reconnaissance sequence using the same native Windows tools Qakbot employed.

The reconnaissance batch script is valuable as a test case because it demonstrates how a real-world threat actor performs structured discovery using only built-in Windows utilities — no dropped tools required. The full command sequence runs: `whoami /all`, `cmd /c set`, `arp -a`, `ipconfig /all`, `net view /all`, `nslookup` (for domain controller enumeration via `_ldap._tcp.dc._msdcs`), `net share`, `route print`, `netstat -nao`, and `net localgroup`. Each command targets a specific type of environmental intelligence: user privileges, environment variables, ARP cache (nearby hosts), network interfaces, accessible shares, domain controller names, local shares, routing table, active connections, and local group memberships.

This technique runs unimpeded with or without Defender — all the commands are native Windows binaries performing routine operations. The undefended dataset therefore reflects normal execution rather than a blocked-and-unblocked scenario.

## What This Dataset Contains

This dataset contains 178 Security events, 41 Sysmon events, 104 PowerShell events, and a rich set of process creation artifacts spanning 18 seconds (22:56:36 to 22:56:54). It is substantially larger than the defended version (33 sysmon, 37 security, 27 PowerShell), with the Security channel growing from 37 to 178 events — primarily due to additional EID 4663 (object access), EID 4907 (security descriptor change), and EID 4670 events from concurrent OS activity in this capture window.

The Security EID 4688 events capture every process in the reconnaissance chain. The key entries:

- PowerShell (PID `0x1598`) spawns `cmd.exe` with `"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1016\src\qakbot.bat"`
- That cmd.exe (PID `0x125c`) spawns the tools in sequence:
  - `whoami /all` — user context with groups and privileges
  - `cmd /c set` — environment variable dump
  - `arp -a` — ARP cache (neighboring hosts)
  - Additional commands including `ipconfig /all`, `net view /all`, `nslookup` DC discovery, `net share`, `route print`, `netstat -nao`, `net localgroup`

Sysmon EID 1 (ProcessCreate) events with the T1033 tag confirm the process hierarchy for `whoami.exe`. The 8 Sysmon EID 3 (NetworkConnect) events are particularly significant: `nslookup` processes making DNS queries to `192.168.4.10:53` (the domain controller's DNS service) for the `_ldap._tcp.dc._msdcs` SRV records — this is the domain controller discovery phase. These network events are absent in the defended version's samples, though both versions may have produced them.

The System channel captures the Windows Modules Installer service (`TrustedInstaller`) changing start type from `demand start` to `auto start` and back — a Windows Update side effect running concurrently. The TaskScheduler channel shows the `SdbinstMergeDbTask` (Application Experience / shim database update) executing via `sdbinst.exe` with return code 0 — again, concurrent background activity unrelated to the technique.

## What This Dataset Does Not Contain

The actual output from any of the Qakbot reconnaissance commands — the user's privilege list, the ARP cache entries, the IP configuration, the route table, the netstat output — is not captured in any event log. All of this information flows through stdout and is visible only to a process monitoring the console or redirected to a file.

The `net view /all` command exits with status `0x2` in this environment (as noted in the defended analysis), indicating a failed network share enumeration — no shares were visible. There are no Sysmon EID 22 (DNS query) events in the samples despite `nslookup` running, though EID 3 network connections to the DNS server are captured.

The PowerShell EID 4104 samples contain only boilerplate. The actual `cmd.exe /c "qakbot.bat"` command line that initiated the batch execution is in the Security 4688 stream but the batch file's internal command sequence is not logged by PowerShell since it runs through cmd.exe.

## Assessment

This dataset is rich in process execution telemetry for a realistic threat actor reconnaissance pattern. The Qakbot batch script sequence — with its characteristic multi-tool chain run from a single cmd.exe via a batch file — is a behavioral pattern that appears across multiple threat actor groups, not just Qakbot. The Sysmon EID 3 network events showing `nslookup` querying the DNS server for domain controller SRV records are particularly valuable, as they represent network-layer evidence that complements the process execution indicators. This dataset is well-suited for building detections around multi-tool reconnaissance sequences and DC discovery via DNS.

## Detection Opportunities Present in This Data

1. Security EID 4688 showing `cmd.exe /c` referencing a batch file named `qakbot.bat` (or any analogous recon batch script in user-writable paths) is a direct indicator — but more importantly, the behavioral pattern of a batch file spawning multiple consecutive discovery tools is the generalizable signal.

2. The sequence of Security EID 4688 events from a single cmd.exe parent showing `whoami /all`, then `arp -a`, then `ipconfig /all`, then `net view /all` in rapid succession (within seconds) is the Qakbot reconnaissance fingerprint, distinguishable from one-off administrative commands.

3. `nslookup -querytype=ALL -timeout=10 _ldap._tcp.dc._msdcs.*` as a command line in Security EID 4688 or Sysmon EID 1 directly identifies domain controller discovery via DNS SRV records — this specific nslookup pattern is a reliable indicator of post-compromise reconnaissance.

4. Sysmon EID 3 (NetworkConnect) from `nslookup.exe` to port 53 on a known domain controller IP, occurring within seconds of `arp -a` and `ipconfig /all` executions in the same cmd.exe session, is a network-process behavioral correlation worth modeling.

5. The full Qakbot sequence can be detected as a temporal cluster: any process tree where the same cmd.exe spawns more than 4 of the following within 30 seconds — `whoami`, `arp`, `ipconfig`, `net view`, `nslookup`, `route`, `netstat`, `net share`, `net localgroup` — strongly indicates automated reconnaissance.

6. Security EID 4663 and EID 4907 volume spikes (109 and 24 events respectively in this dataset) occurring in the same time window as process creation events for multiple discovery tools can corroborate a reconnaissance scenario even when command-line logging is not available.
