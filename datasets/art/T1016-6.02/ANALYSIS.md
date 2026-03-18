# T1016-6: System Network Configuration Discovery — AdFind: Enumerate Active Directory Subnet Objects

## Technique Context

T1016 System Network Configuration Discovery, when targeted at Active Directory, goes well beyond understanding the local host's network stack. Active Directory Subnet objects (`CN=Subnets,CN=Sites,CN=Configuration,DC=...`) map IP address ranges to AD sites, which in turn determine which domain controllers authenticate users, which GPOs apply, and how network traffic routes through the domain. Enumerating these objects gives an attacker a map of the organization's physical and logical network topology.

AdFind is a free, lightweight LDAP query tool created by Joe Richards that has become a standard component of threat actor toolkits — it appears in hands-on-keyboard intrusions from ransomware groups to nation-state actors. Its compact size, lack of installation requirements, and ability to query any LDAP-accessible attribute make it highly effective for rapid AD reconnaissance. The ART test here runs AdFind with the filter `(objectcategory=subnet)` to retrieve all subnet-to-site mappings.

In the defended version, the cmd.exe process exited with status `0x1` and no AdFind process creation appeared in Sysmon, suggesting Defender may have blocked AdFind. In the undefended run, with Defender disabled, AdFind should execute and successfully query the domain controller. However, the dataset events suggest a concurrent Windows Update (TrustedInstaller) activity dominated the capture window.

## What This Dataset Contains

The dataset spans approximately 3 seconds (22:56:25 to 22:56:28). The Security channel's EID 4688 events capture the key evidence. The process chain begins with PowerShell (PID `0x564`) spawning `whoami.exe` for user context checking, then spawning `cmd.exe` with:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f (objectcategory=subnet)
```

The Security channel also shows `TrustedInstaller.exe` (PID `0x1d4`) being spawned by the Services Controller (PID `0x2f4`) with command line `C:\Windows\servicing\TrustedInstaller.exe`, and a Windows Servicing Stack (`amd64_microsoft-windows-servicingstack_31bf38...`) process executing — both are concurrent Windows Update activity in this capture window.

The Security EID 4624 (logon) and EID 4672 (special privileges assigned, including `SeTcbPrivilege`) events reflect the TrustedInstaller service's logon as SYSTEM, not the AdFind technique.

The Sysmon EID 1 events capture `whoami.exe` (PID 1912) with the T1033 rule tag, confirming the pre-execution user discovery. Sysmon EID 17 shows the PowerShell named pipe `\PSHost.134180025826872843.1380.DefaultAppDomain.powershell`. Sysmon EID 11 captures `TrustedInstaller.exe` creating `C:\Windows\Logs\CBS\CBS.log` — the Windows Update activity.

Crucially, unlike the defended version, there is no event with exit status `0x1` for cmd.exe in the available samples — and the full channel has 6 EID 4688 events vs. 10 in the defended version. The smaller count here (with Defender disabled) may reflect fewer Defender-triggered child processes rather than a successful vs. failed execution difference.

Compared to the defended version (19 sysmon, 10 security, 34 PowerShell), the undefended run is smaller (13 sysmon, 22 security, 104 PowerShell). The PowerShell event count increase from 34 to 104 events suggests more internal PowerShell activity in the undefended test framework execution.

## What This Dataset Does Not Contain

There are no Sysmon EID 3 (network connection) events showing AdFind making LDAP connections to the domain controller (`192.168.4.10`). If AdFind executed successfully, it would make an LDAP connection (port 389) to the DC — the absence of this event is a meaningful gap. It could indicate AdFind's execution was outside the Sysmon network monitoring window, or that AdFind returned quickly due to the domain configuration of `acme.local`.

The AdFind process creation itself (the actual `AdFind.exe` process) does not appear in the Sysmon EID 1 samples — only `whoami.exe` and `wevtutil.exe` appear in the sampled events. With only 4 total EID 1 events in the channel, the AdFind execution may not have generated a Sysmon process creation event if the Sysmon configuration filters short-lived processes.

The System channel's single EID 10010 event (`{0A886F29-465A-4AEA-8B8E-BE926BFAE83E} did not register with DCOM within the required timeout`) is a DCOM timeout error, likely from concurrent update activity, not from the AdFind execution.

## Assessment

This dataset provides the key process execution evidence (Security EID 4688 with the AdFind command line and subnet filter) needed for building AdFind-specific detections. However, the absence of network connection telemetry and the competition from concurrent TrustedInstaller activity limits the richness of the dataset for comprehensive AdFind detection scenarios. The most actionable content is the command-line evidence in the Security channel. For building detections that cover AdFind's LDAP activity (network connections, potentially Kerberos authentication), this dataset would need to be supplemented with domain controller-side logs.

## Detection Opportunities Present in This Data

1. Security EID 4688 showing `cmd.exe` spawning with a command line containing `AdFind.exe` is immediately actionable — AdFind is exclusively an AD reconnaissance tool and has no legitimate administrative use case that would justify suppressing alerts on it.

2. The specific AdFind filter `-f (objectcategory=subnet)` in the command line targets network topology information — this is a more targeted indicator than AdFind presence alone, suggesting deliberate network mapping rather than accidental execution.

3. Sysmon EID 1 for a process named `AdFind.exe` (regardless of path) with any command line arguments is a high-confidence indicator. The binary name alone is sufficient for an alert given AdFind's near-exclusive use in adversarial contexts.

4. The `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` path pattern is specific to ART test environments, but in real-world attacks AdFind is typically placed in user directories, `%TEMP%`, or `C:\Windows\Temp`. Behavioral detections should match on the binary name rather than path.

5. The parent chain PowerShell (SYSTEM) → cmd.exe → AdFind.exe with `(objectcategory=subnet)` filter and no corresponding legitimate administrative justification is the full execution pattern for this test.

6. If AdFind executed successfully, Sysmon EID 3 events showing TCP connections from `AdFind.exe` (or its parent cmd.exe) to port 389 on a domain controller IP would confirm the LDAP query — the absence of these events in this dataset is worth investigating in environments with full Sysmon network monitoring enabled.
