# T1112-55: Modify Registry — Do Not Connect to Windows Update

## Technique Context

T1112 (Modify Registry) targeting Windows Update connectivity is a defense evasion and impact technique. Setting `DoNotConnectToWindowsUpdateInternetLocations` to `1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` prevents Windows from reaching Microsoft's update servers, effectively blocking the delivery of security patches to the system.

This technique serves two adversarial purposes. First, it prevents the system from receiving patches that might fix vulnerabilities the attacker is currently exploiting or planning to exploit. Second, it prevents Microsoft's Defender signature updates from being delivered through the Windows Update channel, leaving the system with stale antivirus definitions even if Defender itself is operational.

The `Policies\Microsoft\Windows\WindowsUpdate` path is the Group Policy-managed location for Windows Update configuration. Writing to this path from a script mimics administrative GPO enforcement, which means the change is treated authoritatively. Legitimate enterprise environments often use WSUS (Windows Server Update Services) and set similar registry values through actual Group Policy; the difference here is that the write originates from an automated script under SYSTEM rather than the Group Policy client.

This technique appears in ransomware pre-staging playbooks: before encrypting a system, ransomware operators disable updates to prevent automatic security patches from disrupting the attack or triggering remediation cycles. Combined with notification suppression (T1112-51) and TamperProtection tampering (T1112-56), this forms part of a multi-step security control degradation sequence visible across this test session.

In the defended variant, this dataset produced 37 Sysmon, 13 Security, and 43 PowerShell events. The undefended capture produced 17 Sysmon, 4 Security, and 36 PowerShell events. The significant reduction in both Sysmon and PowerShell events in the undefended run suggests the defended variant triggered additional Defender-related processes and PowerShell activity that does not appear here.

## What This Dataset Contains

The process creation chain is captured in Sysmon EID 1 and Security EID 4688. `cmd.exe` (PID 4628) was spawned by PowerShell (PID 2840) with:

```
"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d 1 /f
```

`cmd.exe` spawned `reg.exe` (PID 1444) with:

```
reg  add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d 1 /f
```

Security EID 4688 records both process creations under `NT AUTHORITY\SYSTEM` with `C:\Windows\TEMP\` working directory for `cmd.exe`.

Sysmon EID 1 also captures `whoami.exe` (PID 5900) executed by PowerShell immediately before the main technique, confirming the ART test framework identity check.

The PowerShell channel (36 EID 4104 events) contains test framework boilerplate and a cleanup call: `Invoke-AtomicTest T1112 -TestNumbers 55 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events. The `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` path is not covered by the sysmon-modular registry monitoring rules. This is a notable gap given that Windows Update policy is a security-relevant configuration target.

The dataset contains no Windows Update service events, no BITS (Background Intelligent Transfer Service) events, and no network telemetry showing failed update connectivity attempts. The impact of the policy change is not visible within this capture window.

The defended variant generated 13 Security events compared to 4 here, suggesting additional process creation events in the defended environment (likely Defender-related) that do not appear in the undefended capture.

## Assessment

This dataset's detection evidence is entirely in process execution telemetry. The value name `DoNotConnectToWindowsUpdateInternetLocations` is lengthy and distinctive — it appears in full in both Security EID 4688 and Sysmon EID 1 command lines. The Windows Update Policies path combined with the specific value name makes the intent explicit.

The absence of Sysmon registry events (EID 12/13) reflects a monitoring gap for this specific path. An environment relying solely on registry-change monitoring for Windows Update policy would miss this modification. Process-based detection and PowerShell logging provide the necessary coverage.

In the broader session context, this modification ran within the same minute as T1112-51 (Defender notifications) and T1112-56 (TamperProtection) — a sequence that collectively degrades Windows security controls across multiple dimensions.

## Detection Opportunities Present in This Data

**`reg.exe` command line containing `DoNotConnectToWindowsUpdateInternetLocations`.** The value name is specific enough to serve as a standalone indicator. Its presence in `reg.exe` arguments is unambiguous evidence of Windows Update blocking.

**Writes to `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` from non-GPO processes.** The `Policies` path is normally managed by the Group Policy client. A direct `reg add` from a script under SYSTEM is anomalous regardless of the specific value being written.

**Windows Update policy modification combined with other security control tampering.** In the broader session, this ran within seconds of Defender notification suppression (T1112-51) and TamperProtection tampering (T1112-56). Detecting multiple `reg add` calls targeting separate security policy registry paths within a narrow time window — particularly under the same SYSTEM session — is a high-confidence indicator of coordinated security degradation.

**The process chain pattern.** PowerShell → cmd.exe → reg.exe under SYSTEM with TEMP working directory, followed by `whoami.exe`, is a repeating signature across all T1112 atomics in this session. Detecting this pattern in association with any sensitive registry path provides coverage even when the specific value name is not known in advance.
