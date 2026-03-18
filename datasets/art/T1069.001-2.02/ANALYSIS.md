# T1069.001-2: Local Groups — Basic Permission Groups Discovery (Windows)

## Technique Context

T1069.001 (Local Groups) is a discovery technique where adversaries enumerate local group memberships to map the privilege landscape on a compromised system. The most common implementation is straightforward: run `net localgroup` to list all local groups, then `net localgroup "Administrators"` to identify who holds local admin rights. This reconnaissance is essential for attackers planning privilege escalation or lateral movement — knowing who belongs to the Administrators, Remote Desktop Users, or Backup Operators groups informs decisions about which credentials to steal, which accounts to impersonate, and which systems are accessible.

Detection focuses on monitoring process creation events for `net.exe` and `net1.exe` with localgroup arguments, the spawning of these tools from unusual parents (especially scripting hosts like PowerShell), and the appearance of enumeration command sequences that combine multiple `net localgroup` calls in rapid succession. Security EID 4799 (A security-enabled local group membership was enumerated) provides direct audit visibility into SAM group membership queries when advanced auditing is enabled.

The ART test for this technique runs both commands via cmd.exe spawned from PowerShell, producing a complete process chain that is representative of how this enumeration appears in real intrusions.

## What This Dataset Contains

This dataset captures a clean, fully successful execution of basic local group enumeration. The event chain is visible across both the Security and Sysmon channels.

Security EID 4688 records the complete process creation sequence: PowerShell spawning `cmd.exe` with the command line `"cmd.exe" /c net localgroup & net localgroup "Administrators"`, followed by `net.exe` executing `net localgroup` and `net localgroup "Administrators"`, and each net.exe process spawning its corresponding `net1.exe` helper:

- `net localgroup` → `C:\Windows\system32\net1 localgroup`
- `net localgroup "Administrators"` → `C:\Windows\system32\net1 localgroup "Administrators"`

The Security channel also records EID 4799 (Security-enabled local group membership enumeration) with `CallerProcessName: C:\Windows\System32\net1.exe`, confirming that the group membership query reached the SAM directly. This event fires specifically for net1.exe querying local group membership, not for the net.exe parent — a subtlety worth noting in detection logic.

Sysmon EID 1 captures all six process creations with full command lines and parent-child relationships: whoami.exe (test framework check), cmd.exe, net.exe, net1.exe, a second whoami.exe, and a bare `cmd.exe /c` (cleanup). The process hierarchy confirms PowerShell → cmd.exe → net.exe → net1.exe, matching the expected execution chain. Sysmon EID 11 records a file write to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`, which is a standard PowerShell profile initialization artifact.

The PowerShell channel (104 events: 102 EID 4104, 2 EID 4103) contains only ART test framework boilerplate — `Set-StrictMode`, `Set-ExecutionPolicy`, error handlers, and `Import-Module` for the ART module. The actual `net` commands are spawned as external processes, so their content does not appear in PowerShell script block logs.

Compared to the defended version (30 sysmon, 18 security, 34 PowerShell events), this undefended dataset shows more PowerShell volume (104 vs 34) and fewer security events (9 vs 18). The defended run generated additional security audit events from Defender's active monitoring; without Defender, the Security channel is leaner, capturing only the core process creation and group membership audit events.

## What This Dataset Does Not Contain

The dataset captures process execution but not the output of the `net localgroup` commands. You will not find the actual list of local groups or their members in any event — the enumerated information was displayed only to the console. There are no LDAP queries or network connections, as this technique enumerates local (not domain) groups via SAM API calls that stay entirely on-host. Windows Security logs do not generate SAM query events beyond EID 4799 for the specific group membership check performed by net1.exe.

The PowerShell channel contains no technique-relevant script blocks because the actual enumeration commands were launched as external child processes rather than run inline in PowerShell.

## Assessment

This is a high-quality, clean dataset for local group enumeration. It covers the complete execution chain from PowerShell through cmd.exe to net.exe and net1.exe, with both Security and Sysmon channels providing complementary visibility. The EID 4799 event directly audits the SAM group membership query with the calling process identified. All processes execute successfully (no ACCESS_DENIED, no abnormal exit codes), making this representative of real-world reconnaissance with an unimpeded execution path.

The dataset is directly useful for detection engineering around the net.exe/net1.exe localgroup enumeration pattern, parent process chain analysis, and correlation between process creation events and SAM audit events.

## Detection Opportunities Present in This Data

1. **Security EID 4688 — net.exe / net1.exe with localgroup arguments**: Both `net localgroup` (enumerate all groups) and `net localgroup "Administrators"` appear as distinct process creation events. The combination of both in sequence, sharing a parent cmd.exe, is characteristic of permission discovery.

2. **Security EID 4799 — SAM group membership enumeration by net1.exe**: The direct audit of SAM group membership provides a high-confidence signal. The `CallerProcessName: C:\Windows\System32\net1.exe` field ties the SAM query back to the net command execution chain.

3. **Sysmon EID 1 — PowerShell spawning cmd.exe spawning net.exe**: The parent process chain PowerShell → cmd.exe → net.exe is unusual in normal operations and characteristic of scripted enumeration. Command line arguments for net.exe containing `localgroup` plus a group name (especially "Administrators") are high-fidelity indicators.

4. **Command sequence correlation**: The appearance of both `net localgroup` and `net localgroup "Administrators"` within the same short time window, sharing a cmd.exe parent from the same PowerShell session, indicates automated enumeration rather than administrative activity.

5. **whoami.exe from PowerShell parent flanking technique execution**: Executions of whoami.exe immediately before and after the net localgroup sequence (visible in EID 4688 and Sysmon EID 1) form a recognizable test framework pattern, useful as a dataset quality marker.
