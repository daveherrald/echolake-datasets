# T1547.002-1: Authentication Package — Authentication Package

## Technique Context

T1547.002 (Authentication Package) is a privileged persistence and credential access technique. Windows allows custom authentication packages to be registered in the LSA (Local Security Authority) by adding a DLL name to `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages`. Because LSA loads registered authentication packages at system startup (running as SYSTEM), and because lsass.exe processes authentication requests, a malicious package DLL gains persistence across reboots and can intercept cleartext credentials during authentication events. This technique requires SYSTEM or Administrator privileges and targets a kernel-level trust boundary.

## What This Dataset Contains

The dataset captures a 7-second window on ACME-WS02 during execution of the ART test that copies a test DLL and modifies the LSA Authentication Packages registry value.

**Sysmon Event 13 (RegistrySetValue)** is the primary indicator, explicitly tagged:

```
RuleName: technique_id=T1547.002,technique_name=Authentication Package
TargetObject: HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages
Details: Binary Data
Image: C:\Windows\system32\reg.exe
```

The value is recorded as "Binary Data" rather than the string content because the sysmon-modular config captures the write but the multi-string registry value type (REG_MULTI_SZ) is rendered as binary in this event.

**PowerShell 4104 script block logging** captures the full ART test payload:

```powershell
Copy-Item "C:\AtomicRedTeam\atomics\T1547.002\bin\package.dll" C:\Windows\System32\
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\0package" /f
```

This confirms that the test added `package` to the Authentication Packages multi-string value alongside the existing `msv1_0` entry, and copied `package.dll` to `C:\Windows\System32\`.

**Sysmon Event 11 (FileCreate)** tagged `technique_id=T1574.010,technique_name=Services File Permissions Weakness` captures the DLL being copied to `C:\Windows\System32\` — the sysmon-modular rule matched on the System32 write path rather than a T1547.002-specific rule.

**Sysmon Event 1 (ProcessCreate):** `whoami.exe` (T1033), `powershell.exe` (T1083), and `reg.exe` (T1083) visible in process creates. The `reg.exe` invocation is captured.

**Sysmon Event 10 (ProcessAccess)** tagged T1055.001 appears as the ART test framework PowerShell instances access each other — test framework artifact.

**Security events (4688/4689/4703):** Three 4688 events (PowerShell spawns), corresponding exits, and a token adjustment. All under SYSTEM context.

The 50 Sysmon events are mostly DLL load (Event 7) artifacts from PowerShell instance initializations; the 39 PowerShell events are predominantly test framework boilerplate.

## What This Dataset Does Not Contain

- **No lsass.exe loading the DLL.** The authentication package DLL is only loaded by lsass.exe at next boot or LSA restart — neither occurred during the collection window. There is no telemetry of `package.dll` being loaded into lsass.
- **No credential interception telemetry.** The DLL copy and registration establish the persistence mechanism; actual credential harvesting would only occur post-reboot.
- **No Security log event 4657.** Registry write auditing is not enabled.
- **No Sysmon DNS or network events.** The test DLL is a benign stub; no network callback was triggered.
- **The DLL copy to System32 triggered a T1574.010 rule, not a T1547.002 rule** in sysmon-modular — detection coverage for the file placement aspect is indirect.

## Assessment

The dataset captures the two concrete artifacts of this technique: the DLL placement into `C:\Windows\System32\` and the modification of the LSA Authentication Packages value. Both are present across Sysmon (Events 11 and 13) and PowerShell logs (4104 script block). Windows Defender did not block either operation — the test DLL is a benign stub, not detected as malware.

The LSA Authentication Packages key is a critical detection point because any modification indicates an attempt to register a new authentication provider, which is an extremely uncommon legitimate action on a workstation. The "Binary Data" representation in the Sysmon 13 event is worth noting: defenders relying on string matching against the value content in Sysmon 13 may miss this write. The PowerShell script block log provides the string-parseable version.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Any write to `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages` is extremely suspicious on a workstation. This is a near-zero false-positive detection opportunity.
- **Sysmon Event 11:** DLL file creation in `C:\Windows\System32\` by `powershell.exe` or `reg.exe` (non-installer processes) is anomalous.
- **PowerShell 4104:** Script blocks containing `Authentication Packages` or references to `msv1_0` alongside new DLL names are high-confidence indicators.
- **Security 4688:** `reg.exe` with command line modifying `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` is detectable via command-line auditing.
- **Sysmon Rule tag:** The EventID 13 carries `technique_id=T1547.002` directly in the RuleName field — the sysmon-modular config has a dedicated rule for this registry path.
