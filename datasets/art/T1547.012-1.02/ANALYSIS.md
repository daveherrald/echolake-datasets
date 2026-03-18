# T1547.012-1: Print Processors — Print Processors

## Technique Context

T1547.012 (Print Processors) achieves persistence by registering a malicious DLL as a Windows print processor under the Print Spooler service. Print processors are DLLs registered at `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\` that `spoolsv.exe` loads when processing print jobs. Because `spoolsv.exe` runs as SYSTEM, any DLL loaded by it gains SYSTEM privileges. This technique requires two steps: (1) copying the DLL to `C:\Windows\System32\spool\prtprocs\x64\` and (2) registering the processor in the registry. It also requires a Spooler restart to activate the DLL.

This is a more complete, operationally realistic persistence technique than many T1547 sub-techniques because it involves both a file drop and a registry write, and — critically — the test includes stopping and restarting the Spooler, which triggers actual DLL loading.

This dataset captures the **undefended** execution of ART test T1547.012-1 on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02) produced 49 sysmon, 25 security, and 37 powershell events. The undefended dataset shows 59 sysmon, 19 security, and 100 powershell events — the higher undefended counts reflect more detailed process lifecycle telemetry in the absence of Defender's process interruption overhead.

## What This Dataset Contains

The dataset spans approximately 12 seconds on ACME-WS06 and contains 178 events across three log sources.

**PowerShell EID 4104** captures the full attack script:

```powershell
if ($(get-service -Name spooler).StartType -eq "Disabled") {Set-Service -Name "spooler" -StartupType Automatic}
net stop spooler
Copy-Item "C:\AtomicRedTeam\atomics\T1547.012\bin\AtomicTest.dll" C:\Windows\System32\spool\prtprocs\x64\AtomicTest.dll
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\AtomicRedTeam" /v Driver /d AtomicTest.dll /t REG_SZ /f
net start spooler
```

The script explicitly stops the Spooler, copies the DLL to the processor directory, registers it, and restarts the Spooler. The DLL name is `AtomicTest.dll` and the processor key name is `AtomicRedTeam`.

**Sysmon (59 events, EIDs 1, 7, 10, 11, 12, 13, 17, 29):**

- **EID 11 (FileCreate):** Two events — the DLL written to `C:\Windows\System32\spool\prtprocs\x64\AtomicTest.dll` (tagged `T1574.010 Services File Permissions Weakness` for the system directory write) and a PowerShell profile artifact.

- **EID 29 (FileExecutableDetected):** `AtomicTest.dll` written to the spool processor directory triggers Sysmon's PE file detection:
  ```
  TargetFilename: C:\Windows\System32\spool\prtprocs\x64\AtomicTest.dll
  Hashes: SHA1=5C29EF53BAEBFA5C19CB040A916C44C9DF39A8B4,
          MD5=C20546941E0281E8E9612D9F240A75D0,
          SHA256=1986501BD94F4087957D13CFECB4B3CEDBE0ECA72678C304F08FDCD...
  ```
  This event fires because Sysmon monitors for new executable files written to sensitive system paths.

- **EID 13 (RegistrySetValue):** The print processor registry registration, tagged `RuleName: UACMe Dir Prep` — a sysmon-modular rule that fires on writes to the Print Processors registry path. The rule name is misleading (it references UACME prep, suggesting it was added for a different purpose), but the event captures the write accurately:
  ```
  Image: C:\Windows\system32\reg.exe
  TargetObject: HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\AtomicRedTeam\Driver
  Details: AtomicTest.dll
  ```

- **EID 12 (RegistryKeyCreate):** The new `AtomicRedTeam` key under Print Processors is captured as a registry key creation event — one of the few datasets in this batch to include EID 12.

- **EID 1 (ProcessCreate):** 15 process creation events including: `whoami.exe` (T1033); `powershell.exe` (T1083) with the full attack payload; `net.exe`/`net1.exe` (T1018) for both `stop spooler` and `start spooler`; `reg.exe` with the full `reg add` command for the print processor registration; `spoolsv.exe` restarting; and the cleanup phase equivalents.

- **EID 10 (ProcessAccess):** Nine events tagged `T1055.001` across multiple child processes.

- **EID 17 (PipeCreate):** Five named pipe creation events.

- **EID 7 (ImageLoad):** 25 DLL load events.

**Security (19 events, EIDs 4688 × 15, 4624 × 2, 4672 × 2):**

- **EID 4688 (Process Create):** 15 events documenting the complete execution chain with command lines: `powershell.exe` with the attack payload, `net.exe stop spooler`, `net1 stop spooler`, `reg.exe` with the full print processor registration command, `net.exe start spooler`, `net1 start spooler`, `spoolsv.exe` restarting, and the cleanup phase.

- **EID 4624 (Logon):** Two service logon events (logon type 5) for the SYSTEM account when `spoolsv.exe` restarts under SYSTEM privileges.

- **EID 4672 (Special Privileges Assigned):** Two events for the SYSTEM account's privileged logon.

The Security channel's `reg.exe` 4688 record documents the processor registration command in full:

```
CommandLine: "C:\Windows\system32\reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\AtomicRedTeam" /v Driver /d AtomicTest.dll /t REG_SZ /f
```

## What This Dataset Does Not Contain

**No Sysmon EID 7 for AtomicTest.dll loading into spoolsv.exe.** The Spooler restart occurs within the test window, which means the DLL should actually load. However, whether Sysmon captured this load depends on the sysmon-modular rules for EID 7 — DLL loads are typically captured only for matches to include rules for suspicious DLL names or paths. `AtomicTest.dll` in `spool\prtprocs\x64\` may not match any explicit EID 7 include rule.

**No print job execution.** The DLL activates on print job processing; no print jobs were submitted during the test window.

**No named T1547.012 Sysmon rule.** The EID 13 fires on the `UACMe Dir Prep` rule rather than a T1547.012-specific rule — the monitoring happened to cover this path but was not designed specifically for print processor persistence.

## Assessment

This is one of the most complete persistence installation datasets in the T1547 batch. The combination of file drop (EID 11 + EID 29), registry write (EID 13 + EID 12), and service lifecycle events (multiple EID 1 and 4688 records for net.exe and spoolsv.exe) creates a multi-source, multi-step attack narrative.

The EID 29 (FileExecutableDetected) event for the DLL in the spool processor directory is particularly valuable — it fires on the file system event and provides cryptographic hashes for the dropped DLL, enabling reputation lookups and future correlation without requiring a registry event to be present.

The Spooler restart sequence (`net stop spooler` → `reg add` → `net start spooler`) combined with the DLL drop to `spool\prtprocs\x64\` is a highly characteristic operation that appears across the Sysmon, Security, and PowerShell channels simultaneously.

## Detection Opportunities Present in This Data

- **Sysmon EID 11 + EID 29:** File creation in `C:\Windows\System32\spool\prtprocs\x64\` by a non-Spooler process. Any DLL dropped to this directory that was not placed there by `spoolsv.exe` itself or a legitimate installer is anomalous.

- **Sysmon EID 13:** Writes to `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\` creating new subkeys or setting `Driver` values. The key path is specific to print processor registration.

- **Sysmon EID 12:** Registry key creation under the Print Processors path — `AtomicRedTeam` (or any non-Microsoft processor name) appearing as a new key under this path.

- **Security EID 4688:** `reg.exe` command lines referencing `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments` or `Print Processors`. The full command line including the `/v Driver /d <dllname>` pattern is specific.

- **Process sequence:** `net.exe stop spooler` followed by `reg.exe` writing to the Print Processors path, followed by `net.exe start spooler` — this three-step sequence in the Security EID 4688 timeline is characteristic of T1547.012 deployment.

- **Service logon correlation:** Security EID 4624 (logon type 5) for `spoolsv.exe` combined with EID 29 for a new DLL in the processor directory indicates the service has been manipulated and restarted with a new untrusted module.
