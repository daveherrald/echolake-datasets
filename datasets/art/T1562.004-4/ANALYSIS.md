# T1562.004-4: Disable or Modify System Firewall — Opening Ports for Proxy - HARDRAIN

## Technique Context

T1562.004 (Disable or Modify System Firewall) includes adding inbound allow rules to permit
attacker-controlled services to receive connections. The "HARDRAIN" test emulates behavior
attributed to the DPRK HARDRAIN implant, which opens a specific inbound port (450 TCP) to support
a proxy/backdoor listener. Creating an inbound allow rule for an unusual high/non-standard port
is a pattern seen across multiple malware families preparing for C2 communication.

## What This Dataset Contains

The test ran `netsh advfirewall firewall add rule name="atomic testing" action=allow dir=in
protocol=TCP localport=450` via `cmd.exe`, spawned from the ART PowerShell test framework under
NT AUTHORITY\SYSTEM.

**Sysmon EID 1 — process creation (19 events, 3 process-create):**
- `cmd.exe /c netsh advfirewall firewall add rule name="atomic testing" action=allow dir=in protocol=TCP localport=450`
- `netsh advfirewall firewall add rule name="atomic testing" action=allow dir=in protocol=TCP localport=450` (child of cmd.exe)
- Preceded by `whoami.exe` (ART test framework pre-check)

**Sysmon EID 13 — registry value set (2 events):**
The Firewall service wrote the new rule and incremented the Epoch counter:
- `HKLM\...\FirewallRules\{6DE3CA31-730F-4A1F-B554-7F4821E5E84D}` — `v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=450|Name=atomic testing|`
- `HKLM\...\FirewallPolicy\...\Epoch\Epoch` — DWORD increment

**Security EID 4688 (12 events):** Process creation for whoami.exe, cmd.exe, and netsh.exe under
SYSTEM. Token Elevation Type 1.

**PowerShell EID 4104 (34 events):** ART test framework boilerplate only. The actual firewall command
was issued via cmd.exe subprocess; no test-specific PowerShell commands are logged.

## What This Dataset Does Not Contain (and Why)

**Windows Firewall audit events (EID 2004/2005):** Security audit policy had `policy_change:
none`, so no firewall rule-change audit records were generated.

**No Sysmon EID 22 (DNS) or EID 3 (network):** The test only modifies firewall policy; it does
not initiate any network connections. Port 450 is opened but nothing connects to it during the
test window.

**No process-access or file events related to payload deployment:** The HARDRAIN test in ART only
creates the firewall rule; it does not drop or execute any implant binary.

**No cleanup-reversal events in this capture window:** The per-test cleanup ran outside the
captured time range.

## Assessment

This is a compact but high-fidelity dataset. The most diagnostic artifact is the Sysmon EID 13
registry write showing `LPort=450|Name=atomic testing` — an unusual port number with an obvious
test name. In real adversary use, the rule name would differ, but the port number and the
`Action=Allow|Dir=In` pattern on an uncommon port remain strong indicators. The process chain
`powershell.exe -> cmd.exe -> netsh.exe advfirewall add rule ... localport=450` is directly
observable in both Sysmon EID 1 and Security EID 4688.

The PowerShell log contributes no test-specific content here; this was a cmd.exe-executed test.

## Detection Opportunities Present in This Data

- **Sysmon EID 1:** `netsh.exe` with arguments `advfirewall firewall add rule` and `localport=` where the port is non-standard (not 80, 443, 3389, 445, etc.)
- **Sysmon EID 1:** `netsh.exe` spawned from `cmd.exe` spawned from `powershell.exe` under SYSTEM with `advfirewall` in the command line
- **Sysmon EID 13:** New `FirewallRules\{GUID}` key written by svchost.exe containing `Dir=In|Protocol=6|LPort=450` or other uncommon port values
- **Security EID 4688:** `netsh.exe` process creation with command-line logging showing `advfirewall firewall add rule ... localport=450`
- **Correlation:** Any inbound firewall rule added for a port not typically seen in enterprise baseline — especially if the rule name is a generic string rather than a recognizable application name
