# T1562.010-2: Downgrade Attack — ESXi - Change VIB Acceptance Level to CommunitySupported via ESXCLI

## Technique Context

MITRE ATT&CK T1562.010 (Downgrade Attack) includes actions that weaken security controls to permit further exploitation. VMware ESXi hosts enforce a VIB (vSphere Installation Bundle) acceptance level hierarchy: `VMwareCertified` → `VMwareSigned` → `PartnerSupported` → `CommunitySupported`. Lowering the acceptance level to `CommunitySupported` allows installation of unsigned or community-authored VIBs, including attacker-deployed backdoor VIBs. This technique was used in UNC3886 operations targeting VMware infrastructure — the attackers lowered the VIB acceptance level, then installed a malicious VIB containing a backdoor that persisted through ESXi reboots. The ESXCLI command to make this change is:

```
esxcli software acceptance set --level CommunitySupported
```

This test simulates the Windows-side execution: connecting to an ESXi host via SSH using `plink.exe` (PuTTY command-line SSH client) and delivering the command via a script file. The target ESXi host (`atomic.local`) is a placeholder that does not resolve in this environment.

## What This Dataset Contains

The dataset spans roughly five seconds and captures 148 events across PowerShell (107) and Security (41) channels.

**Security (EID 4688):** Five process creation events. PowerShell (parent) spawns a `cmd.exe` with what appears to be an empty or minimal command (the sample shows `"cmd.exe" /c ` with no further content visible — the command may have been truncated or contained an empty prerequisite check). The full `plink.exe` invocation from the defended variant would be:

```
cmd.exe /c echo "" | "C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe" "atomic.local" -ssh -l "root" -pw "pass" -m "C:\AtomicRedTeam\atomics\T1562.010\src\esx_community_supported.txt"
```

**Security (EID 4703):** Two token right adjustment events. One is for `lsass.exe` (PID 0x310) enabling a large set of SYSTEM privileges including SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeSecurityPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege — this is a normal lsass.exe privilege assertion, not attack-related. The second is for `powershell.exe`.

**Security (EID 4689):** Ten process exit events.

**Security (EID 4798):** Five user local group membership enumeration events, all from `C:\Windows\System32\wbem\WmiPrvSE.exe` (PID 0x1064, SYSTEM) enumerating local accounts: `Administrator`, `DefaultAccount`, `mm11711`, `Guest`, and `WDAGUtilityAccount`. This is WMI-provider-initiated account enumeration — background system management activity from the WMI infrastructure, not related to the technique.

**Security (EID 4799):** 19 security-enabled local group membership enumeration events, all from `C:\Program Files\Cribl\bin\cribl.exe` (PID 0x15f4, SYSTEM). Cribl Edge (the log collection agent) is enumerating local groups: `Access Control Assistance Operators`, `Administrators`, `Backup Operators`, `Cryptographic Operators`, `Distributed COM Users`, `Device Owners`, `Event Log Readers`, `Guests`, `IIS_IUSRS`, and others. This is the Cribl Edge agent performing routine privilege/membership discovery as part of its instrumentation — a real-world artifact of the collection infrastructure.

**PowerShell (EID 4103 + 4104):** 107 events. Three EID 4103 events record test framework-level cmdlets. EID 4104 events are predominantly boilerplate, with `Set-ExecutionPolicy Bypass -Scope Process -Force` and `$ErrorActionPreference = 'Continue'` as the notable non-boilerplate entries.

## What This Dataset Does Not Contain

**No `plink.exe` process creation event.** As with T1562.004-23 and T1562.004-25, `plink.exe` is not captured in EID 4688 by the Security audit policy, and Sysmon is absent from this dataset. In the defended variant, Sysmon EID 1 also failed to capture `plink.exe`.

**No Sysmon events.** The defended variant captured 17 Sysmon events including EID 1 (process creates), EID 10 (process access), EID 11 (file creates), and EID 17 (named pipe). None is present here.

**No network connection events.** `atomic.local` does not resolve. No Sysmon EID 3 or EID 22 events appear. The SSH connection was never established.

**No ESXi-side telemetry.** ESXi VIB acceptance level changes, if successful, would appear in ESXi syslog and vSphere audit logs on the target host. This dataset captures only the Windows workstation.

**No VIB installation.** Lowering the acceptance level is a prerequisite for VIB installation, not the installation itself. Even if the ESXi connection had succeeded, this dataset would only show the acceptance level change, not any subsequent VIB installation.

## Assessment

The technique attempted to lower the ESXi VIB acceptance level from a Windows workstation. The connection failed because `atomic.local` does not exist in this environment. The core forensic evidence is limited to the `cmd.exe` process creation event showing the attack intent.

A notable aspect of this dataset is the Cribl Edge group enumeration activity (19 EID 4799 events from `cribl.exe`). This is authentic telemetry from the log collection agent itself performing routine system discovery — it demonstrates that collection infrastructure generates its own Security events that co-occur with attack telemetry. These events are not filtered out because they represent real Windows activity, not test framework artifacts.

The WMI-initiated user enumeration (5 EID 4798 events from `WmiPrvSE.exe`) is similarly authentic background activity — WMI-based management queries regularly enumerate local account information on Windows systems.

Compared to the defended variant (17 Sysmon + 12 Security + 33 PowerShell = 62 total), the undefended run produced 107 PowerShell + 41 Security events (148 total). The Security channel is dramatically richer in the undefended run (41 vs. 12 events) due to the Cribl Edge group enumeration events (19 EID 4799) and WMI account enumeration (5 EID 4798) that were captured within this test's time window. These events were present in the environment during both runs but were filtered or absent from the defended sample.

## Detection Opportunities Present in This Data

- **Security EID 4688 (cmd.exe command line, if fully captured):** The `plink.exe` invocation with `esx_community_supported.txt` as the command file path is a high-specificity indicator. Any `plink.exe` invocation referencing ESXi-related command files or using `-l root` against non-Windows targets warrants investigation.
- **Security EID 4688 (process chain):** `powershell.exe` → `cmd.exe` → `plink.exe` (even if plink is not directly visible in EID 4688) under SYSTEM context is an unusual pattern when the cmd.exe command line references non-standard executable paths.
- **EID 4799 (Cribl Edge group enumeration):** In environments using Cribl Edge as a collection agent, regular group enumeration events from `cribl.exe` will appear in datasets near attack activity. These should be baselined and excluded from alerting to prevent false positives.
- **EID 4798 (WmiPrvSE.exe account enumeration):** WMI-initiated local account enumeration is a routine Windows background activity. Its presence near attack telemetry is coincidental and should not be conflated with attacker reconnaissance.
- **ESXi-side monitoring (out of scope):** `esxcli software acceptance set --level CommunitySupported` in ESXi audit logs, VIB installation events in vSphere, or changes to `/etc/vmware/acceptance.xml` on ESXi hosts are the definitive indicators of this technique's success — none of which are captured in this Windows-side dataset.
