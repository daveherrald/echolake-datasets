# T1547.002-1: Authentication Package — Authentication Package

## Technique Context

T1547.002 (Authentication Package) is a privileged persistence mechanism targeting the Windows Local Security Authority (LSA). Windows supports custom authentication packages — DLLs registered in the LSA's `Authentication Packages` multi-string value at `HKLM\System\CurrentControlSet\Control\Lsa`. Because LSA loads all registered packages at system startup and runs them inside `lsass.exe` (which runs as SYSTEM), a malicious authentication package DLL achieves persistent execution with the highest possible privileges on a Windows system. It also gains direct access to plaintext credentials during authentication events. This technique requires SYSTEM or administrator rights to modify the Lsa registry key and to drop a DLL in `C:\Windows\System32\`.

This dataset captures the **undefended** execution of ART test T1547.002-1 on ACME-WS06 with Defender completely disabled. The defended variant (ACME-WS02, Defender active) produced 50 sysmon, 12 security, and 39 powershell events — nearly identical to the undefended 45 sysmon, 6 security, and 112 powershell events. Defender does not block the DLL copy or registry modification in this test; the higher undefended PowerShell count reflects additional test framework script block fragments logged on this host configuration.

## What This Dataset Contains

The dataset covers approximately 7 seconds on ACME-WS06 and contains 163 events across three log sources.

**PowerShell EID 4104** captures the full test payload:

```powershell
Copy-Item "C:\AtomicRedTeam\atomics\T1547.002\bin\package.dll" C:\Windows\System32\
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\0package.dll" /f
```

The two-step operation is explicit: first the DLL is staged to `C:\Windows\System32\`, then the `Authentication Packages` value is modified to include `package.dll` alongside the existing `msv1_0` entry. A cleanup script block is also captured, reversing both operations.

**Sysmon (45 events, EIDs 1, 7, 10, 11, 13, 17):**

- **EID 13 (RegistrySetValue):** The primary persistence indicator, explicitly tagged:
  ```
  RuleName: technique_id=T1547.002,technique_name=Authentication Package
  TargetObject: HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages
  Details: Binary Data
  Image: C:\Windows\system32\reg.exe
  ```
  The value content is recorded as "Binary Data" because the REG_MULTI_SZ type is rendered as binary in Sysmon EID 13. The rule name confirms sysmon-modular has an explicit T1547.002 rule for this path.

- **EID 11 (FileCreate):** The DLL copy to `C:\Windows\System32\` is captured, tagged `technique_id=T1574.010,technique_name=Services File Permissions Weakness`. The sysmon-modular rule matched on the System32 write path, not a T1547.002-specific rule. This is a common sysmon-modular tag for DLL drops in system directories.

- **EID 1 (ProcessCreate):** Six process creation events including: `whoami.exe` (T1033, pre-check); `powershell.exe` (T1083) with the full DLL-copy + reg-add payload; `reg.exe` (T1083) executing `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v "Authentication Packages" /t REG_MULTI_SZ /d msv1_0\0package.dll /f`; and a second `powershell.exe` for the cleanup step with a corresponding `reg.exe` resetting the value to `msv1_0` only.

- **EID 10 (ProcessAccess):** Six events tagged `T1055.001` — the test framework PowerShell acquiring handles to child processes.

- **EID 17 (PipeCreate):** Three named pipe creation events for PowerShell host runtime.

- **EID 7 (ImageLoad):** 25 DLL load events for PowerShell instance initialization.

**Security (6 events, all EID 4688):** Process creation records for both PowerShell instances and both `reg.exe` invocations, with full command lines. The Security log independently documents both the attack payload and its cleanup:

```
CommandLine: reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v "Authentication Packages" /t REG_MULTI_SZ /d msv1_0\0package.dll /f
```

```
CommandLine: reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v "Authentication Packages" /t REG_MULTI_SZ /d msv1_0 /f
```

Both the malicious modification and the cleanup are recorded, which allows analysts reviewing post-incident logs to see the full lifecycle.

## What This Dataset Does Not Contain

**No LSASS DLL loading.** The authentication package DLL is only loaded by `lsass.exe` at the next system boot. No Sysmon EID 7 for `package.dll` loading into `lsass.exe` is present — that event would only appear after a reboot, which is outside this dataset's time window.

**No lsass.exe process access or modification.** No EID 10 targeting `lsass.exe` as the TargetImage is present. The persistence was installed via registry modification, not through direct LSASS manipulation.

**No file hash for the dropped DLL.** The EID 11 event records the file write but the `Hashes` field for `package.dll` is not in the samples. The DLL was copied from `C:\AtomicRedTeam\atomics\T1547.002\bin\package.dll` and is a test placeholder, not a functional credential-harvesting library.

**No Security EID 4657 (Registry Object Access).** Registry write auditing via the SACL-based object access audit policy is not enabled; the registry modification is captured by Sysmon EID 13, not by Security audit events.

## Assessment

This dataset provides complete coverage of the persistence installation phase: DLL staging to System32 (Sysmon EID 11), registry modification to the LSA Authentication Packages value (Sysmon EID 13 with explicit T1547.002 rule tag), process creation records for the tooling used (Security EID 4688 and Sysmon EID 1), and the full script payload in PowerShell EID 4104.

The sysmon-modular configuration has an explicit named rule for the `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages` path, making this one of the better-detected persistence techniques in this batch. Unlike HKCU Winlogon (T1547.004-1) where the registry write is invisible to Sysmon, this technique is directly tagged.

What is absent — and would be present in an actual attack scenario — is the post-reboot evidence of the DLL loading into LSASS. For complete coverage of the full technique lifecycle, you would need to correlate this dataset with Sysmon EID 7 events from a subsequent system startup showing `package.dll` (or whatever the real payload is named) loading into `lsass.exe`.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 (tagged T1547.002):** The sysmon-modular ruleset explicitly names this technique for the `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages` path. Any write to this value warrants immediate investigation.

- **Sysmon EID 11:** DLL files written to `C:\Windows\System32\` by PowerShell, cmd, or other scripting hosts are anomalous. The combination of a DLL drop to System32 followed by a write to an LSA registry value is a high-confidence indicator.

- **Security EID 4688:** `reg.exe` command lines referencing `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` with `/v "Authentication Packages"` and `/t REG_MULTI_SZ`. This is a specific, searchable command-line pattern.

- **PowerShell EID 4104:** Script blocks containing `Copy-Item` targeting `C:\Windows\System32\` combined with `reg add` targeting the LSA `Authentication Packages` path, or `Set-ItemProperty` targeting `HKLM:\System\CurrentControlSet\Control\Lsa`.

- **Correlation:** The two-step nature of this technique (file drop + registry write) means an analyst can correlate EID 11 (file create in System32) with EID 13 (LSA registry write) within the same process or time window. Both steps are necessary and observable; either alone is suspicious, both together are indicative.
