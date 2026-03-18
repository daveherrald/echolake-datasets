# T1543.003-4: Windows Service — TinyTurla Backdoor Service w64time

## Technique Context

T1543.003 (Windows Service) at its most sophisticated uses service names and descriptions designed to blend with legitimate Windows infrastructure. TinyTurla is a backdoor attributed to Turla (a Russian state-sponsored APT group) that installs itself as a service named `W64Time` — a near-mimic of the legitimate `W32Time` (Windows Time) service — with display name "Windows 64 Time" and a description matching the real service. The DLL is loaded via a shared `svchost.exe` service group (`-k TimeService`), further mimicking the legitimate time service. This technique demonstrates two evasion layers: masquerading service name/description and using `svchost.exe` as a DLL-hosting process rather than a standalone service executable. Detection focuses on service names that closely resemble legitimate Windows services, `svchost.exe` services loading DLLs from unexpected paths, and the `ServiceDll` registry value pointing to a non-Microsoft DLL.

## What This Dataset Contains

The test replicates TinyTurla's installation sequence using a compound `cmd.exe` command:

```
copy "C:\AtomicRedTeam\atomics\T1543.003\bin\w64time.dll" %systemroot%\system32\
sc create W64Time binPath= "c:\Windows\System32\svchost.exe -k TimeService" type=share start=auto
sc config W64Time DisplayName= "Windows 64 Time"
sc description W64Time "Maintain date and time synch on all clients and services in the network"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost" /v TimeService /t REG_MULTI_SZ /d "W64Time" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W64Time\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%systemroot%\system32\w64time.dll" /f
sc start W64Time
```

All seven operations — `copy`, `sc create`, `sc config`, `sc description`, two `reg add`, and `sc start` — succeed (`0x0` exit codes for `sc.exe`, `reg.exe`, and `cmd.exe`).

**System Event ID 7045** records the service installation:
- Service Name: `W64Time`
- Service File Name: `c:\Windows\System32\svchost.exe -k TimeService`
- Service Type: user mode service
- Service Start Type: auto start

**System Event ID 7023** records the immediate service failure: `The Windows 64 Time service terminated with the following error: The specified module could not be found.` The DLL was copied to System32 but the `svchost.exe` service host could not load it (likely because the `w64time.dll` in the ART kit is a stub or incompatible binary).

**Sysmon Event ID 11** records `cmd.exe` creating `C:\Windows\System32\W64Time.dll` with RuleName `technique_id=T1574.010,technique_name=Services File Permissions Weakness`.

**Sysmon Event ID 13** records `services.exe` writing seven registry values to `HKLM\System\CurrentControlSet\Services\W64Time`: `Start`, `ErrorControl`, `Type`, `ImagePath`, `ObjectName`, `DisplayName`, and `Description`. A separate Sysmon 13 records `reg.exe` writing `HKLM\System\CurrentControlSet\Services\W64Time\Parameters\ServiceDll` with the DLL path.

Security 4688 captures the full compound command line including all seven operations.

## What This Dataset Does Not Contain

**No svchost.exe loading w64time.dll.** The service failed to start (`ERROR_MOD_NOT_FOUND`), so no DLL image-load events appear for the malicious DLL. In a successful deployment, Sysmon Event ID 7 (ImageLoad) from `svchost.exe` loading `w64time.dll` from System32 would appear.

**No Security account management events** for the service account.

**No Sysmon registry write for `Svchost\TimeService`** group registration — the `reg add` to `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost` did not trigger a Sysmon ID 13, likely because this registry path falls outside the Sysmon-modular include rules for service-related registry keys.

## Assessment

This is the richest of the four T1543.003 datasets for detection engineering purposes. It combines command-line evidence (`sc create`, `sc config`, `sc description`, `reg add ServiceDll`), System 7045 (service installation with the svchost-group `ImagePath`), System 7023 (immediate failure — a realistic artifact), Sysmon registry writes for both the service key and the `ServiceDll` parameter, and file creation of the DLL in System32. The masquerading detail — `W64Time` vs. `W32Time`, description copied from the real service — makes this dataset useful for training detection rules that look beyond exact name matches to similarity scoring or description-matching.

## Detection Opportunities Present in This Data

1. **System Event ID 7045**: New service with `binPath` containing `svchost.exe -k` and a group name not matching any existing `svchost` group — `svchost`-hosted service with a novel group name.
2. **Sysmon Event ID 13**: `reg.exe` writing `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll` with a value pointing to a non-Microsoft DLL path — the canonical indicator for `svchost`-hosted malicious services.
3. **System Event ID 7023**: Service failure immediately after 7045 installation — `The specified module could not be found` after installing a `svchost`-group service; indicates a malformed or stubbed DLL.
4. **Service name similarity**: `W64Time` vs. `W32Time` — near-typosquat of a legitimate Windows service name; detection based on Levenshtein distance or prefix matching against known service names.
5. **Sysmon Event ID 11**: DLL file created in `%SystemRoot%\System32` by `cmd.exe` or a non-`services.exe` process — unexpected DLL drop in System32 tagged with `T1574.010`.
6. **Sysmon Event ID 13**: `services.exe` writing `Description` to a new service key with text matching known-legitimate service descriptions — description masquerading.
7. **Security 4688**: `sc.exe description <name> "<text>"` where `<text>` matches a known Windows service description — explicit description spoofing in command line.
