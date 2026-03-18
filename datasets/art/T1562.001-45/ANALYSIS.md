# T1562.001-45: Disable or Modify Tools — AMSI Bypass - Override AMSI via COM

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes bypassing the Antimalware Scan Interface (AMSI), which allows Windows security products to scan script and buffer content at runtime. This test overrides the AMSI COM server registration by writing a fake `InProcServer32` path under `HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}` — the CLSID for the AMSI COM object (`amsi.dll`). By redirecting the COM registration to a non-existent DLL (`C:\IDontExist.dll`), the AMSI object fails to instantiate, causing AMSI scanning to silently fail for processes that honor per-user COM registration. This technique targets user-hive COM redirection rather than system-level AMSI patching, making it stealthier than in-memory approaches.

## What This Dataset Contains

**Security (4688):** Two process creation events capture the execution chain. A parent PowerShell spawns `cmd.exe` with:
```
"cmd.exe" /c REG ADD HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32 /ve /t REG_SZ /d C:\IDontExist.dll /f
```
`cmd.exe` then spawns `reg.exe` executing the same `REG ADD` command directly. Both processes exit with status 0x0.

**Sysmon Event 13 (RegistryValue Set):** The registry write is captured:
```
HKU\.DEFAULT\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32\(Default) = C:\IDontExist.dll
```
Note the key appears under `HKU\.DEFAULT` (the SYSTEM account's user hive) rather than `HKCU`, reflecting that the test runs as `NT AUTHORITY\SYSTEM`.

**Sysmon Event 1:** `cmd.exe` and `reg.exe` process creation events with full command lines. A `whoami.exe` event is also present — part of the ART test framework pre-execution identity check.

**PowerShell (4104):** The ART test framework `Set-ExecutionPolicy Bypass` script block is present. No technique-specific PowerShell content was logged because the actual technique uses `cmd.exe` and `reg.exe` rather than PowerShell cmdlets.

## What This Dataset Does Not Contain (and Why)

**No AMSI bypass validation:** The dataset captures the registry write but not any subsequent test of whether AMSI is now disabled. No process that loads AMSI and attempts a scan is present.

**No Sysmon ProcessCreate for reg.exe from cmd.exe:** The Sysmon include-mode ProcessCreate filter does not match plain `reg.exe` invocations in all cases. The Security 4688 log provides this coverage gap's complement.

**No in-memory AMSI patching:** This is a COM registration approach. No memory writes, `VirtualProtect` calls, or `WriteProcessMemory` events are present — those would appear with a different AMSI bypass technique.

**No Defender block:** Defender with AMSI enabled did not prevent this registry write. The write targets the user hive and does not directly modify `amsi.dll` or any Defender-protected path.

## Assessment

The technique executed successfully. The CLSID redirection was written (Sysmon 13 confirms the value), and both `cmd.exe` and `reg.exe` exited cleanly. The dataset provides strong coverage via Sysmon 13 with the exact CLSID `{fdb00e52-a214-4aa1-8fba-4357bb0072ec}` and path `IDontExist.dll`, plus process creation with full command lines. The CLSID value is a reliable, specific indicator.

## Detection Opportunities Present in This Data

- **Sysmon 13:** Registry write to `CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32` under any user hive — highly specific AMSI COM override indicator
- **Sysmon 13:** Any `InProcServer32` write pointing to a non-existent or unusual DLL path — broader AMSI/COM hijacking pattern
- **Security 4688 / Sysmon 1:** `reg.exe` with `CLSID` and `InProcServer32` in the command line — detectable at process creation
- **Security 4688:** `cmd.exe` spawning `reg.exe` with `HKCU\Software\Classes\CLSID` and a DLL path — suspicious COM registration modification pattern
- **Temporal correlation:** PowerShell test framework process followed immediately by cmd → reg chain targeting a security-related CLSID
