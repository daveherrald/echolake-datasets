# T1562.004-24: Disable or Modify System Firewall — Set a Firewall Rule Using New-NetFirewallRule

## Technique Context

T1562.004 (Disable or Modify System Firewall) includes creating new inbound allow rules using
Windows PowerShell cmdlets. `New-NetFirewallRule` is the native PowerShell alternative to netsh
and is the preferred approach in modern attacker tooling and scripts because it integrates
directly with the NetSecurity module without spawning a child process. Attackers use it to
create persistent inbound rules that survive reboots and are harder to spot than netsh commands
in process trees.

## What This Dataset Contains

The test ran `New-NetFirewallRule -DisplayName "New rule" -Direction "Inbound" -LocalPort "21"
-Protocol "TCP" -Action "allow"` in a PowerShell subprocess launched by the ART test framework under
NT AUTHORITY\SYSTEM.

**Sysmon EID 1 — process creation (60 events, 3 process-create):**
- `powershell.exe & {New-NetFirewallRule -DisplayName "New rule" -Direction "Inbound" -LocalPort "21" -Protocol "TCP" -Action "allow"}` (parent: WmiPrvSE.exe)
- `whoami.exe` (ART test framework pre-check)
- WmiPrvSE.exe itself (spawned to handle the guest-agent WMI call)

**Sysmon EID 13 — registry value set (2 events):**
The Firewall service wrote the new rule:
- `HKLM\...\FirewallRules\{64461156-043c-4aa4-8953-a2bdb252171d}` — `v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=21|Name=New rule|`
- `Epoch\Epoch` increment

**Sysmon EID 22 — DNS query (1 event):** A DNS query occurred in this window, unrelated to the
firewall operation itself.

**Security EID 4688 (14 events):** Process creation for WmiPrvSE.exe, whoami.exe, and
powershell.exe. All SYSTEM-context with Token Elevation Type 1.

**Security EID 4703 (3 events):** Token right adjusted events — normal side-effect of process
creation under SYSTEM.

**PowerShell EID 4104 (36 events):** Two script blocks contain the test command:
```
& {New-NetFirewallRule -DisplayName "New rule" -Direction "Inbound" -LocalPort "21" -Protocol "TCP" -Action "allow"}
```
The remaining 34 blocks are ART test framework boilerplate (error-handling lambdas).

**System EID 7040 (1 event):** BITS service start type changed from auto to demand. This is
background OS behavior unrelated to the test.

## What This Dataset Does Not Contain (and Why)

**No child netsh.exe process:** Unlike the netsh-based tests, `New-NetFirewallRule` operates
via the NetSecurity COM object within the PowerShell process — no separate netsh.exe is spawned.
The entire operation happens inside powershell.exe.

**Windows Firewall audit events (EID 2004/2005):** Not collected due to `policy_change: none`
audit policy.

**No Sysmon EID 3 (network):** The rule is created but no connection is made to port 21.

**Sysmon ProcessCreate include-mode filtering** means many routine powershell.exe child process
events may have been suppressed, but the test-relevant powershell.exe invocation was captured via
the T1518.001 (Security Software Discovery) include rule.

## Assessment

This dataset highlights the key distinguishing feature of `New-NetFirewallRule` versus netsh:
the absence of a netsh.exe child process. Detection strategies relying solely on netsh.exe
command-line monitoring will miss this technique. The most reliable indicators are the PowerShell
EID 4104 script block (which exposes the cmdlet and all parameters) and the Sysmon EID 13
registry write showing `LPort=21|Name=New rule`. Port 21 (FTP) is unusual for an inbound rule
on a workstation. Test executed successfully.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Script block containing `New-NetFirewallRule` with `Direction "Inbound"` and an uncommon `LocalPort` — direct, high-fidelity indicator
- **Sysmon EID 13:** New `FirewallRules\{GUID}` value written by svchost.exe with `Dir=In` and an uncommon port (e.g., `LPort=21`)
- **Sysmon EID 1:** `powershell.exe` with `New-NetFirewallRule` in the command line — catches cases where the cmdlet is passed directly vs. via script block
- **Security EID 4688:** `powershell.exe` process creation under SYSTEM where the parent is WmiPrvSE.exe (indicates remote/automated execution)
- **Absence of netsh.exe:** If a new firewall rule appears (EID 13 registry write) but no netsh.exe was spawned, `New-NetFirewallRule` or a COM-based approach is the likely vector
