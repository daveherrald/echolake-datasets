# T1546.007-1: Netsh Helper DLL — Netsh Helper DLL Registration

## Technique Context

T1546.007 (Netsh Helper DLL) abuses the Windows `netsh.exe` network configuration utility's extensibility mechanism. `netsh.exe` loads DLLs listed under `HKLM\SOFTWARE\Microsoft\NetSh` as helper modules that extend its command set. An attacker who registers a malicious DLL as a netsh helper gains code execution every time any user or process runs `netsh.exe` on the system — including automated tasks and network diagnostics. Because `netsh.exe` is a trusted system binary, this technique can blend with legitimate traffic and survive EDR process-based detections. The DLL is loaded at process startup (not on a specific command), so it runs in the context of whoever invokes netsh. Detection teams focus on writes to `HKLM\SOFTWARE\Microsoft\NetSh` from non-system processes and DLL loads by `netsh.exe` from non-standard paths.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-13 23:39:04–23:39:09) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (33 events, IDs: 1, 7, 10, 11, 13, 17):** The technique evidence is concentrated in a small number of high-value events. Sysmon ID=13 (RegistryValueSet) is the most precise indicator:

```
RuleName: technique_id=T1546.007,technique_name=Netsh Helper DLL
EventType: SetValue
Image: C:\Windows\system32\netsh.exe
TargetObject: HKLM\SOFTWARE\Microsoft\NetSh\NetshHelper
Details: C:\AtomicRedTeam\atomics\T1546.007\bin\NetshHelper.dll
User: NT AUTHORITY\SYSTEM
```

This event is tagged by sysmon-modular with the exact technique ID. The execution chain is visible in Sysmon ID=1 events:

1. `whoami.exe` (tagged T1033, test framework context check)
2. `cmd.exe` with: `"cmd.exe" /c netsh.exe add helper "C:\AtomicRedTeam\atomics\T1546.007\bin\NetshHelper.dll" & taskkill /im notepad.exe /t /f > NUL 2>&1`
3. `netsh.exe` with: `netsh.exe add helper "C:\AtomicRedTeam\atomics\T1546.007\bin\NetshHelper.dll"`
4. `cmd.exe` spawning `notepad` via `C:\Windows\system32\cmd.exe /c start notepad` (to demonstrate DLL trigger)
5. `taskkill.exe` to clean up (tagged T1489)

Security channel 4688 events confirm all five processes with their command lines.

**Security (18 events, IDs: 4688, 4689, 4703):** All five process creations and their terminations are captured, with command-line arguments confirming the netsh helper registration and the `notepad` trigger test.

**PowerShell (34 events, IDs: 4103, 4104):** Test framework boilerplate only — `Set-StrictMode` and `Set-ExecutionPolicy Bypass`.

## What This Dataset Does Not Contain

- **No Sysmon ID=7 (ImageLoad) for the helper DLL:** Although the DLL loads when netsh runs, the sysmon-modular configuration does not include an image load rule matching helper DLLs from non-standard paths loaded by `netsh.exe`. The DLL execution is confirmed only by the registry write.
- **No DLL execution payload evidence:** The `NetshHelper.dll` in the ART test is benign (it launches notepad), but there is no Sysmon ID=3 (NetworkConnect) or further process chain showing notepad's launch originating from the netsh DLL load — Sysmon does not capture that DLL→process relationship.
- **No persistence trigger after cleanup:** The test registers, demonstrates, and then removes the helper in the same run. There is no dataset showing the DLL loading on a subsequent `netsh.exe` invocation.

## Assessment

This is a well-captured dataset with the highest-value event — Sysmon ID=13 for the `HKLM\SOFTWARE\Microsoft\NetSh` write — present and properly tagged. The full execution chain from `cmd.exe` through `netsh.exe` to the registry write is visible in both Sysmon and Security channels. The dataset is immediately usable for both command-line–based and registry-write–based detections. Adding a Sysmon ID=7 include rule for DLLs loaded by `netsh.exe` from paths outside `C:\Windows\System32` would enable a powerful fileless detection path complementary to the registry write.

## Detection Opportunities Present in This Data

1. **Sysmon ID=13:** A registry value set under `HKLM\SOFTWARE\Microsoft\NetSh` by any process other than a Windows update mechanism is a high-confidence indicator — legitimate netsh helper registration is rare on workstations.
2. **Sysmon ID=1 / Security ID=4688:** `netsh.exe` invoked with `add helper` and a DLL path outside `C:\Windows\System32` is directly alertable; this is not a valid administrative use case on most endpoints.
3. **Security ID=4688:** `cmd.exe` launching `netsh.exe add helper <non-system-path>.dll` as part of a compound command (chained with `&`) is an unusual command-line pattern.
4. **Sysmon ID=1:** The chain PowerShell → cmd.exe → netsh.exe with a non-standard argument is suspicious even without the registry evidence — `netsh.exe` is rarely a direct child of cmd.exe in normal operations.
5. **Composite:** A Sysmon ID=13 write to `HKLM\SOFTWARE\Microsoft\NetSh\*` paired with a subsequent Sysmon ID=1 for `netsh.exe` (or vice versa) within a short time window confirms registration and test execution, narrowing investigation scope significantly.
