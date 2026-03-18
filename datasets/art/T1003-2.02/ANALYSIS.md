# T1003-2: OS Credential Dumping — Credential Dumping with NPPSpy

## Technique Context

NPPSpy demonstrates one of the more elegant persistence-as-credential-theft patterns in the Windows ecosystem. The attack installs a malicious Network Provider DLL that registers itself in the Windows authentication chain, intercepting plaintext credentials before they reach legitimate providers. Windows passes credentials through the provider chain defined in `HKLM\System\CurrentControlSet\Control\NetworkProvider\Order\PROVIDERORDER` during authentication events, meaning every user who authenticates to a network resource after installation hands their cleartext password to the attacker. The technique is insidious because the malicious DLL is loaded by legitimate Windows processes and survives reboots without requiring any scheduled tasks, services, or startup entries beyond the registry configuration.

Detection of NPPSpy and its variants centers on a handful of high-fidelity indicators: modifications to the `PROVIDERORDER` registry value, creation of a new service key under `HKLM\System\CurrentControlSet\Services\` with a `NetworkProvider` subkey, placement of an unexpected DLL in `C:\Windows\System32\`, and DLL image loads tagged against the Network Provider or Credential Access technique IDs. The technique requires SYSTEM-level privileges to install but does not require Defender to be disabled for the installation phase itself — the DLL copy and registry writes are not inherently malicious Windows API calls.

For this undefended dataset, the full installation chain should produce artifacts that the defended variant missed: specifically, Sysmon EID 11 file creation events for the DLL being placed in System32, and potentially EID 7 image load events if the provider is loaded during the dataset's time window.

## What This Dataset Contains

This dataset captures the complete NPPSpy installation across four Windows event channels. The execution spans roughly five seconds (22:41:42Z to 22:41:47Z) on ACME-WS06.

The **Security channel** (7 events) provides the process execution backbone. EID 4688 events record the full process chain: a parent PowerShell process (PID 0x144c) spawning child PowerShell instances and two `whoami.exe` processes (PIDs 0xc58 and 0x474), indicating the ART test framework running the test and its cleanup phase. A `svchost.exe` (PID 0x6a4) spawned by `services.exe` (PID 0x2f4) also appears, consistent with Windows registering the new Network Provider. EID 4624 (Logon Type 5 — Service) and EID 4672 (Special Privileges assigned to SYSTEM) appear alongside, reflecting the elevated context under which the installation runs.

The **PowerShell channel** (103 EID 4104 events) captures the script block execution trail. The `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'` block confirms test framework setup, and the cleanup block `Invoke-AtomicTest T1003 -TestNumbers 2 -Cleanup` shows both the test and its cleanup ran. The defended version's analysis noted that `Copy-Item "C:\AtomicRedTeam\atomics\..\ExternalPayloads\NPPSPY.dll" -Destination "C:\Windows\System32"` appeared in the PowerShell channel in the defended run, and that registry modification script blocks were visible. The undefended run has 103 EID 4104 events versus 58 in the defended run — the additional 45 events likely include the technique-specific script blocks that were present in the defended run but may have been sampled differently here.

The **Sysmon channel** (3,335 events) is dominated by EID 11 file creation events (3,312 total), reflecting an active Windows Update operation running concurrently via `svchost.exe` writing manifests to `C:\Windows\SoftwareDistribution\Download\`. The attack-specific Sysmon events are present in the EID breakdown — 11 EID 7 (Image Load) events, 4 EID 10 (Process Access), 4 EID 1 (Process Create), 3 EID 17 (Pipe Create), and critically **1 EID 13 (Registry Value Set)** event. The defended run showed only 50 Sysmon events total, with the EID 13 events confirming the `PROVIDERORDER` and `NPPSpy` service key modifications. The undefended run's single sampled EID 13 event was not drawn in the 20-sample window, but its presence in the EID breakdown confirms the registry telemetry is in the dataset.

The **System channel** contributes a single EID 566 event recording a session transition from state 0 to state 1 (SessionUnlock), providing timing context for when the workstation's interactive session was active.

The key difference from the defended variant is scale and completeness. The defended version noted that the NPPSPY.dll file copy to System32 was absent — Defender blocked that file operation. In this undefended run, the file copy should have succeeded, meaning the full EID 11 file creation artifact for `C:\Windows\System32\NPPSPY.dll` should be present in the dataset (it would appear among the 3,312 EID 11 events, outside the 20-sample window). The EID 13 registry event confirming `PROVIDERORDER` was updated to include `NPPSpy` is also present.

## What This Dataset Does Not Contain

The dataset does not capture any post-installation credential harvesting. NPPSpy requires a user authentication event to trigger — a network logon after the provider is registered — and no such event occurs within the five-second window covered here. The `C:\NPPSpy.txt` file where harvested credentials would be written is therefore absent.

The 20-event random sample drawn for Sysmon is entirely consumed by Windows Update manifest writes, making it difficult to surface the attack-specific EID 1, 7, 10, and 13 events without filtering. Analysts working with this dataset should query specifically for those EIDs rather than relying on the sample view.

There are no Sysmon EID 3 (Network Connection) events indicating the DLL calling out to a C2 after credential capture — NPPSpy writes locally to a text file rather than exfiltrating over the network.

## Assessment

This dataset represents a complete, undefended NPPSpy installation. The combination of PowerShell script block logging, Security EID 4688 process creation, Sysmon EID 13 registry modification (confirming the `PROVIDERORDER` change and `NPPSpy` service key creation), and — unlike the defended version — the Sysmon EID 11 file creation for `NPPSPY.dll` in System32 provides a full detection engineering reference for all phases of the attack. The concurrent Windows Update activity adds realistic environmental context that analysts will encounter in production. This dataset is particularly useful for tuning rules that distinguish malicious DLL drops to System32 from legitimate update activity based on the originating process.

## Detection Opportunities Present in This Data

1. Sysmon EID 13 matching `TargetObject` containing `NetworkProvider\Order\PROVIDERORDER` with a `Details` value that adds an unexpected provider name — this is the highest-fidelity indicator of NPPSpy installation.

2. Sysmon EID 13 matching creation of `HKLM\System\CurrentControlSet\Services\NPPSpy\NetworkProvider\` keys — specifically the `ProviderPath` value pointing to a DLL in System32.

3. Sysmon EID 11 with `TargetFilename` matching `C:\Windows\System32\*.dll` where the creating process is `powershell.exe` — a DLL placed directly by PowerShell into System32 is a strong anomaly signal.

4. Security EID 4688 with `NewProcessName` containing `powershell.exe` and command line containing both `Copy-Item` and `System32` in the same argument string.

5. PowerShell EID 4104 script blocks containing `NetworkProvider` registry key paths or the string `PROVIDERORDER` — these will appear across the 103 script block events in this dataset.

6. Correlation of Sysmon EID 7 (Image Load) events where an unknown or recently-added DLL is loaded by `lsass.exe` or `svchost.exe` with `RuleName` tagging against Network Provider or credential access techniques — triggered when Windows reloads providers after the registry change.
