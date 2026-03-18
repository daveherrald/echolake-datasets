# T1547.003-1: Time Providers — Create a New Time Provider

## Technique Context

T1547.003 (Time Providers) achieves persistence through the Windows Time Service (W32Time) DLL plugin architecture. W32Time loads registered time provider DLLs at service startup, executing them inside `svchost.exe` under the `NT AUTHORITY\LOCAL SERVICE` account. An attacker creates a new provider key under `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\`, sets the `DllName` value to point to a malicious DLL, and enables it with `Enabled=1`. The DLL loads the next time W32Time starts — which can be triggered immediately by stopping and restarting the service.

This is an evasion-friendly technique: the Windows Time Service is present on every domain-joined Windows host, provider registration is an obscure and infrequently monitored path, and the loaded DLL runs in a trusted `svchost.exe` process. This technique requires administrator privileges.

This dataset captures the **undefended** execution of ART test T1547.003-1 on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02) produced 58 sysmon, 27 security, 38 powershell, and 6 system events, compared to the undefended 64 sysmon, 18 security, 102 powershell, and 6 system events. The higher undefended powershell count reflects host-specific test framework behavior. The undefended sysmon count is slightly higher, capturing additional process creates from the expanded service lifecycle.

## What This Dataset Contains

The dataset spans approximately 8 seconds on ACME-WS06 and contains 190 events across four log sources — making this one of the most telemetry-rich datasets in the T1547 batch.

**PowerShell EID 4104** captures the full attack script:

```powershell
net stop w32time
Copy-Item "C:\AtomicRedTeam\atomics\T1547.003\bin\AtomicTest.dll" C:\Users\Public\AtomicTest.dll
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest" /t REG_SZ /v "DllName" /d "C:\Users\Public\AtomicTest.dll" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest" /t REG_DWORD /v "Enabled" /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest" /t REG_DWORD /v "InputProvider" /d 1 /f
net start w32time
```

The three `reg add` commands create the provider key and set all required values. The DLL is staged to `C:\Users\Public\AtomicTest.dll` — a world-writable path chosen to avoid needing System32 write access for the DLL itself (only the registry write requires elevation).

**Sysmon (64 events, EIDs 1, 7, 10, 11, 13, 17, 22, 29):**

- **EID 13 (RegistrySetValue):** At least one event captured in the samples, targeting `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient\SpecialPollTimeRemaining` — a legitimate W32Time service reaction to the restart, not the attack payload. The three attack-specific registry writes (`DllName`, `Enabled`, `InputProvider`) are present in the full dataset (64 total events include EID 13) but are captured in events not included in the 20-event sample. The full dataset contains the attack-specific EID 13 writes as confirmed by the PowerShell and Security event records of the `reg add` executions.

- **EID 1 (ProcessCreate):** 13 process creation events including: `whoami.exe` (T1033), `powershell.exe` (T1083) with the full attack payload, `net.exe` (T1018) and `net1.exe` (T1018) for both the stop and start operations, and three `reg.exe` invocations (one per provider attribute). The W32Time service restart also generates a `svchost.exe` process create.

- **EID 22 (DNSQuery):** `svchost.exe` queries `ACME-DC01.acme.local` — the domain controller's hostname resolved for NTP synchronization after the service restarts. This is a legitimate side-effect of the service lifecycle manipulation, not an attacker action, but it confirms the service actually restarted.

- **EID 29 (FileExecutableDetected):** The DLL staged to `C:\Users\Public\AtomicTest.dll` triggers Sysmon's file executable detection, tagged `technique_id=T1059.001`. Sysmon monitors for new PE files written to world-writable or user-writable paths and fires this event on detection. The `Hashes` field provides SHA1, MD5, and SHA256 for `AtomicTest.dll`.

- **EID 11 (FileCreate):** Three file creates including the DLL write to `C:\Users\Public\AtomicTest.dll`.

- **EID 10 (ProcessAccess):** 10 events tagged `T1055.001` — test framework process handle acquisition for child processes.

- **EID 17 (PipeCreate):** Four named pipe creation events.

- **EID 7 (ImageLoad):** 26 DLL load events for PowerShell initialization.

**Security (18 events, EIDs 4688 × 15, 4662 × 2, 4616 × 1):**

- **EID 4688:** 15 process creation events covering the full attack chain: `powershell.exe` with the attack payload, all three `reg.exe` invocations with complete command lines, `net.exe`/`net1.exe` for service stop/start, the restarted `svchost.exe` for W32Time.

- **EID 4616 (System Time Changed):** The W32Time restart caused a 15ms time adjustment, generating a Security audit event with source `NT AUTHORITY\LOCAL SERVICE`. This is a direct observable consequence of the `net stop w32time` / `net start w32time` sequence and confirms the service was operationally disrupted and restored.

- **EID 4662 (Object Operation):** Two events for `NT AUTHORITY\LOCAL SERVICE` performing a read operation on `Policy\Secrets\$MACHINE.ACC` in the LSA store — a normal Kerberos machine account secret access that occurs when the W32Time service synchronizes with the domain controller after restart.

**System (6 events, EIDs 1, 24, 37, 135):**

- **EID 37 (Time Provider Synchronized):** W32Time reporting successful synchronization with `ACME-DC01.acme.local`.
- **EID 135 (NTP Error):** Two events with `ErrorMessage: The entry already exists. (0x800706E0)` for peer `192.168.4.10` — a transient W32Time error during provider reconfiguration.
- **EID 1 (Time Change):** Confirms the 15ms adjustment (`TimeDeltaInMs: 15`).
- **EID 24 (Time Zone Info):** Time zone information cache update.

## What This Dataset Does Not Contain

**No DLL loading into svchost.exe for the provider.** The `AtomicTest.dll` provider is registered and the service is restarted within this test window — but the dataset does not contain a Sysmon EID 7 event showing `AtomicTest.dll` actually loading into `svchost.exe`. Whether the DLL loaded and whether Sysmon captured the load would require reviewing the full sysmon channel rather than the 20-event sample. Given the service restart occurred within the window, the load may be present in the full 64-event sysmon log.

**No cleanup-phase registry deletes.** The cleanup script (`net stop w32time; reg delete ...; rm AtomicTest.dll; net start w32time`) is present in PowerShell EID 4104, but cleanup execution events may fall outside the sample window.

## Assessment

This dataset is operationally significant because it documents a complete execution of the persistence mechanism including the service restart that would actually load the malicious provider. The combination of registry writes, DLL staging, service lifecycle events, and legitimate side-effects (NTP sync, time adjustment) creates a rich, cross-source story.

The System log events are particularly valuable for detection: Security EID 4616 (time change) and System EID 37/135 (W32Time sync events) correlate with the `net stop`/`net start w32time` sequence. An analyst seeing unexpected W32Time service restarts combined with registry writes to `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` should treat this as a high-priority indicator of T1547.003.

The sysmon-modular configuration does not have a named T1547.003 rule for the W32Time provider path — the EID 13 events fire on the default catch-all rule. This is a monitoring gap: the W32Time TimeProviders path is a known persistence location that warrants an explicit include rule.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** Registry writes to `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` creating new subkeys or setting `DllName` values. Any non-Microsoft provider registration in this path is anomalous.

- **Security EID 4688:** `reg.exe` command lines referencing the W32Time TimeProviders path with `/v DllName` or `/v Enabled`. The combination of these arguments is specific to time provider DLL registration.

- **Sysmon EID 29 (FileExecutableDetected):** A PE file written to `C:\Users\Public\` or other world-writable paths by a scripting host. World-writable DLL staging is a common preparation step for this technique.

- **Security EID 4616 (Time Changed) + EID 4688 (net.exe stop/start w32time):** Unexpected W32Time service restarts coinciding with time adjustments indicate service lifecycle manipulation. This correlation across Security and System logs is a strong indicator.

- **System EID 135 (NTP Error):** Transient NTP errors following service stops/starts can correlate with time service manipulation.

- **Sysmon EID 1:** `net.exe stop w32time` followed closely by `reg.exe` writes to the W32Time TimeProviders path, then `net.exe start w32time`. This three-step sequence in the process timeline is characteristic of T1547.003 deployment.
