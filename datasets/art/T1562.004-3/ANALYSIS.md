# T1562.004-3: Disable or Modify System Firewall — Allow SMB and RDP on Microsoft Defender Firewall

## Technique Context

T1562.004 (Disable or Modify System Firewall) covers adversary actions that weaken host firewall
controls to enable lateral movement or remote access. Enabling RDP and SMB inbound rules is a
concrete, high-value step: it prepares the host to receive lateral movement over port 3389 or 445
without the OS blocking the connection. This is a common post-exploitation step by ransomware
operators, nation-state actors, and commodity malware alike.

## What This Dataset Contains

The test ran `netsh advfirewall firewall set rule group="remote desktop" new enable=Yes` and
`netsh advfirewall firewall set rule group="file and printer sharing" new enable=Yes` via cmd.exe,
spawned from a PowerShell parent (itself launched by the ART test framework under NT AUTHORITY\SYSTEM).

**Sysmon EID 1 — process creation (99 events, 4 process-create):**
- `cmd.exe /c netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & netsh advfirewall firewall set rule group="file and printer sharing" new enable=Yes`
- `netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`
- `netsh advfirewall firewall set rule group="file and printer sharing" new enable=Yes`

**Sysmon EID 13 — registry value set (66 events):**
The Windows Firewall service (svchost.exe as NT AUTHORITY\LOCAL SERVICE) wrote the full rule
definitions directly to the registry, producing highly specific indicators:
- `HKLM\...\FirewallRules\RemoteDesktop-Shadow-In-TCP` — `v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=...RdpSa.exe|...`
- `HKLM\...\FirewallRules\RemoteDesktop-UserMode-In-TCP` — `LPort=3389`
- `HKLM\...\FirewallRules\RemoteDesktop-UserMode-In-UDP` — `LPort=3389`
- `HKLM\...\FirewallRules\FPS-SMB-In-TCP` — `LPort=445`
- `HKLM\...\FirewallRules\FPS-NB_Session-In-TCP` — `LPort=139`
- `HKLM\...\FirewallRules\Epoch\Epoch` — incremented on every rule change

The 66 EID 13 events reflect that enabling both groups re-applies every rule in each group; the
Epoch counter increments with each write, producing a burst of sequential DWORD updates alongside
the actual rule value writes.

**Security EID 4688 (14 events):** Process creation for whoami.exe (ART test framework pre-check),
cmd.exe, and two netsh.exe instances. Token Elevation Type 1 (default) — no UAC prompt because
the test framework already runs as SYSTEM.

**PowerShell EID 4104 (34 events):** PowerShell script block logging captures the ART test framework
wrapper. The actual command was issued via cmd.exe; the PS blocks are test framework boilerplate
(`Set-StrictMode`, `$_.PSMessageDetails`, etc.) with no test-specific content.

## What This Dataset Does Not Contain (and Why)

**Windows Firewall audit events (EID 2004/2005/2006):** The Security audit policy had
`policy_change: none`, so Microsoft-Windows-Windows Firewall With Advanced Security events were
not collected. Those events would provide direct, structured rule-add/remove records.

**No Sysmon EID 22 (DNS):** netsh.exe does not perform DNS lookups for this operation.

**No network connection events:** This test only modifies the firewall policy; it does not
initiate or accept any connections. Sysmon EID 3 (network connect) is absent because no outbound
connections occurred.

**Full 4688 command lines are truncated** in the Security log due to the event message field
width — the complete argument strings appear only in Sysmon EID 1.

## Assessment

This is a high-fidelity dataset for the "enable RDP/SMB via netsh group rule" pattern. The
Sysmon EID 13 burst showing 60+ registry writes to `FirewallRules\` and `Epoch\Epoch` is the
clearest indicator of mass rule modification. The process chain
`powershell.exe -> cmd.exe -> netsh.exe` with the specific group names `"remote desktop"` and
`"file and printer sharing"` is highly characteristic. The test executed successfully and
completely — all expected registry writes are present.

The 34 PowerShell EID 4104 events are largely ART test framework overhead (error-handling lambdas, etc.)
rather than attack content.

## Detection Opportunities Present in This Data

- **Sysmon EID 1:** `netsh.exe` with command line containing `advfirewall firewall set rule group="remote desktop"` or `group="file and printer sharing"` with `enable=Yes`
- **Sysmon EID 1:** `cmd.exe` parent of `netsh.exe` where `netsh` arguments include `advfirewall` and a firewall group name
- **Sysmon EID 13:** Burst of writes to `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\RemoteDesktop-*` within a short time window
- **Sysmon EID 13:** `Epoch\Epoch` counter incrementing rapidly (10+ increments in under 200ms) by svchost.exe indicates bulk firewall rule modification
- **Security EID 4688:** `netsh.exe` with command-line audit showing `advfirewall` arguments
- **Correlation:** netsh.exe with firewall group modification arguments appearing under a PowerShell or cmd.exe parent running as SYSTEM
