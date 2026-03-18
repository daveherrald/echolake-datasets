# T1518.001-1: Security Software Discovery — Security Software Discovery

## Technique Context

T1518.001 (Security Software Discovery) covers adversary enumeration of defensive tooling — endpoint protection, firewalls, monitoring agents, EDR sensors, and SIEM forwarders — to understand the detection landscape before proceeding with higher-risk actions. This is a standard pre-exploitation and post-compromise step: knowing whether Defender, Sysmon, CrowdStrike, or Carbon Black is present directly informs attacker tool selection, evasion priorities, and timing. The breadth of this test (firewall configuration queries, Windows Defender service checks, Sysmon process queries, and tasklist with keyword filtering) is representative of the automated reconnaissance executed by frameworks like Cobalt Strike and Meterpreter during initial host assessment. Detection engineering for this technique focuses on the combination of multiple security-tool-specific queries within a short time window from a common parent process.

## What This Dataset Contains

This is the largest and most event-rich dataset in this batch. The ART test executes a single `cmd.exe` command that chains 17 separate sub-commands using `&` to enumerate firewall state and security software in one shot. The full command:

```
"cmd.exe" /c netsh.exe advfirewall show allprofiles & netsh.exe advfirewall firewall dump &
netsh.exe advfirewall show currentprofile & netsh.exe advfirewall firewall show rule name=all &
netsh.exe firewall show state & netsh.exe firewall show config &
sc query windefend &
powershell.exe /c "Get-Process | Where-Object { $_.ProcessName -eq 'Sysmon' }" &
powershell.exe /c "Get-Service | where-object {$_.DisplayName -like '*sysm*'}" &
powershell.exe /c "Get-CimInstance Win32_Service -Filter 'Description = ''System Monitor service'''" &
tasklist.exe & tasklist.exe | findstr /i virus & tasklist.exe | findstr /i cb &
tasklist.exe | findstr /i defender & tasklist.exe | findstr /i cylance &
tasklist.exe | findstr /i mc & tasklist.exe | findstr /i "virus cb defender cylance mc"
```

**Sysmon (Event ID 1)** — 16 distinct `ProcessCreate` events are captured for the children of this `cmd.exe`, tagged with appropriate sysmon-modular annotations:
- Six `netsh.exe` invocations, all tagged `technique_id=T1518.001`
- `sc.exe query windefend` tagged `technique_id=T1543.003`
- Three child `powershell.exe` processes querying Sysmon by process name, display name, and CimInstance service description
- `tasklist.exe` (multiple) and `findstr.exe` with vendor-specific keywords (`virus`, `cb`, `defender`, `cylance`, `mc`)

The sysmon-modular config correctly tagged `netsh.exe` invocations as T1518.001, demonstrating that the ruleset has specific coverage for the firewall enumeration pattern.

**Security (Event ID 4688)** — All 16+ child process creates appear with full command lines, providing a complete sequential record of the reconnaissance chain. The parent `cmd.exe` command line with all 17 chained commands is visible in both the `cmd.exe` 4688 event and as the creator process for each child.

**PowerShell (Event ID 4104)** — Three script blocks are captured from the three child `powershell.exe` invocations:
- `Get-Process | Where-Object { $_.ProcessName -eq 'Sysmon' }`
- `Get-Service | where-object {$_.DisplayName -like '*sysm*'}`
- `Get-CimInstance Win32_Service -Filter 'Description = ''System Monitor service'''`

These blocks show three distinct methods for detecting Sysmon: by process name, by service display name wildcard, and by service description (the internal description string of the Sysmon service). The last method is a more evasive approach used when Sysmon is installed with a custom service name.

**PowerShell (Event ID 4103)** — Module logging is present for the test framework `Set-ExecutionPolicy` calls and for the inner filter script blocks from the `Where-Object` and `where-object` calls.

**Security (Event IDs 4688, 4689)** — 58 total events (process creates and exits) covering the full execution chain. The 4689 exit events confirm all enumeration processes completed (most with exit status 0x0, indicating successful execution).

## What This Dataset Does Not Contain

- No output of any command. Stdout is not captured in Windows event logs; you cannot determine from this dataset whether Sysmon was found running, whether Defender was active, or what firewall rules exist.
- `tasklist.exe` itself does not appear in Sysmon Event 1 — the sysmon-modular include-mode filter does not match `tasklist.exe` without additional arguments. Security 4688 captures it.
- `findstr.exe` does not appear in Sysmon Event 1 for the same reason. Security 4688 captures all `findstr.exe` invocations.
- No Security 4663 (object access) events for registry or service reads — object access auditing is not enabled.

## Assessment

This is the strongest dataset in this batch for detection engineering. The breadth of the test — firewall, AV, EDR, and monitoring agent queries all from a single parent `cmd.exe` within a 9-second window — produces a rich set of correlated events across Sysmon, Security, and PowerShell channels. The sysmon-modular annotations correctly identify T1518.001 on the netsh events, and the three different Sysmon detection methods in the PowerShell script blocks are excellent training data for behavioral detection of attacker anti-detection reconnaissance. The 110 Sysmon events and 58 security events provide ample context for rule tuning. The main limitation is the absence of command output, which is inherent to Windows event log collection.

## Detection Opportunities Present in This Data

1. **Sysmon Event 1 burst** — Multiple security-tool-specific process creates (`netsh.exe advfirewall`, `sc query windefend`, `tasklist | findstr /i defender`) within a short window from a single `cmd.exe` parent is a strong behavioral cluster indicator.
2. **Security 4688 — `sc query windefend`** — Querying the Windows Defender service status from a non-administrative GUI context is anomalous; the Security event captures this with full parent chain.
3. **PowerShell 4104** — `Get-Process` or `Get-Service` filtering on `Sysmon` or `sysm*` in a script block is a targeted Sysmon detection attempt; alert at medium-high severity with context.
4. **PowerShell 4104** — `Get-CimInstance Win32_Service -Filter 'Description = ''System Monitor service'''` is a rare, specific query targeting Sysmon's service description — attackers use this to find renamed Sysmon instances.
5. **Sysmon Event 1 with `technique_id=T1518.001`** — netsh firewall enumeration commands are pre-tagged by sysmon-modular and can be alerted on directly.
6. **Security 4688 — `findstr.exe` keyword list** — `findstr /i "virus cb defender cylance mc"` with a vendor keyword list is a pattern seen in attacker scripts enumerating AV/EDR processes; the multi-keyword variant is more specific than single-vendor filters.
7. **Chain correlation** — A single `cmd.exe` spawning `netsh.exe` (×6), `sc.exe`, `powershell.exe` (×3), `tasklist.exe` (×7), and `findstr.exe` (×6) within 1 second is a timing-based cluster detection opportunity: alert when any parent spawns more than 3 of these binaries within 5 seconds.
