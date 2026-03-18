# T1003.002-5: Security Account Manager — Dump Volume Shadow Copy Hives with certutil

## Technique Context

T1003.002 targets the SAM database for credential extraction. One challenge with dumping the SAM via `reg.exe` is that it requires the process to have administrative access to the live registry hive while Windows is running. Volume Shadow Copies (VSS) provide a way around this: a VSS snapshot captures the filesystem at a point in time, and files that are locked in the live system (like the SAM, SYSTEM, and SECURITY hives) are accessible through the shadow copy path `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[N]\Windows\System32\config\`.

This test uses `certutil.exe` to copy the credential hives from a volume shadow copy. Certutil is a Living off the Land Binary (LOLBin) — a legitimate Windows certificate management utility — repurposed here for file operations. The specific pattern is `certutil -f -split -urldecode [source] [dest]` with the VSC path as the source. Detection engineers focus on this technique because certutil abuse is a common red team tactic, and the combination of certutil with shadow copy paths is a well-known indicator.

The defended version was blocked by Defender before the hive files could be extracted. This undefended dataset shows the complete execution including multiple certutil invocations.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**Security channel (21 events: 14x EID 4688, 7x EID 5379):** The 14 EID 4688 events are striking — this is the highest process creation count among the T1003.002 variants. The events show `powershell.exe` spawning `whoami.exe` (pre-check), `cmd.exe`, then a cascade of `certutil.exe` processes (PIDs 0xd78, 0xb64, 0xc60, 0x948, 0xec8, 0x16e0, 0x12fc, 0x16ac, 0x13b8, 0x1634 — ten separate `certutil.exe` invocations), followed by `whoami.exe` (post-check) and `cmd.exe` (cleanup). Ten certutil processes in rapid sequence suggests the test iterates through multiple shadow copies or multiple hive files per shadow copy. This is the most distinctive process creation pattern in this batch.

**Sysmon channel (23 events: 14x EID 1, 4x EID 10, 3x EID 13, 1x EID 7, 1x EID 11):** The 14 EID 1 process creation events mirror the Security log's 14 EID 4688 events. Critically, the Sysmon EID 1 events include full command lines: the certutil processes carry `RuleName: technique_id=T1202,technique_name=Indirect Command Execution` — Sysmon's rules flagging certutil as a LOLBin execution mechanism. Three Sysmon EID 13 (registry value set) events capture certutil writing to `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptDllFindOIDInfo\` keys — this is certutil registering its own OID handlers as it initializes, a consistent artifact of certutil execution regardless of what it's actually doing. The EID 11 file creation event from `powershell.exe` writing to `StartupProfileData-Interactive` is routine PowerShell profile data.

**PowerShell channel (104 events: 102x EID 4104, 2x EID 4103):** Import-Module and the standard ART test framework blocks are present.

**Compared to the defended dataset (sysmon: 36, security: 30, powershell: 34):** The defended run generated 30 Security events vs. 21 undefended, and 36 Sysmon events vs. 23 — more logging in the defended version. This counterintuitive result occurs because Defender's real-time protection generates its own security events as it intercepts and blocks activity. The undefended run had fewer overall events but the activity that did occur actually completed (hive files were written). The PowerShell event count is notably higher undefended (104 vs. 34), confirming full script execution.

## What This Dataset Does Not Contain

The certutil command lines in the Sysmon EID 1 events show the `T1202 Indirect Command Execution` rule name but do not expose the full argument strings in the 20-event sample. The shadow copy path arguments (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[N]\...`) would be visible in the full command line fields. No VSS creation events (EID 29 or Volume Shadow Copy service events) appear here — the shadow copy was presumably already present, or its creation is captured in a different dataset. File creation events for the actual SAM/SYSTEM/SECURITY hive files would appear in EID 11 but are not in the 20-event sample.

## Assessment

The cascade of ten certutil process creations is the most visually distinctive aspect of this dataset. The combination of certutil invoked by cmd.exe (itself spawned by PowerShell as SYSTEM), the `T1202 Indirect Command Execution` Sysmon rule hits, and the certutil OID registry writes in EID 13 together provide layered detection coverage. This dataset is particularly useful for tuning certutil-based detection logic, as it shows what a real volume-copy hive extraction with certutil looks like end-to-end.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — multiple certutil processes in rapid sequence:** Ten certutil.exe processes spawned within seconds from the same parent cmd.exe is a strong anomaly. Even a single certutil invocation from PowerShell as SYSTEM warrants investigation, but the cascade pattern is highly distinctive.

2. **Sysmon EID 1 — T1202 rule name on certutil:** The Sysmon configuration flags certutil as `technique_id=T1202,technique_name=Indirect Command Execution` — detecting certutil invocations via this rule name, especially when the parent is cmd.exe which was spawned by PowerShell as SYSTEM, provides a direct behavioral signal.

3. **Sysmon EID 13 — certutil OID registry writes:** Certutil writing to `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptDllFindOIDInfo\` is a consistent initialization artifact that can be correlated with process creation to confirm certutil ran, even if command line logging is disabled.

4. **EID 4688 — certutil spawned outside of certificate management context:** On a domain workstation, certutil.exe being invoked by cmd.exe that was itself spawned by powershell.exe running as SYSTEM with no network connectivity indicators is suspicious. Legitimate certutil use typically involves network-accessible PKI infrastructure.

5. **Sysmon EID 11 — hive file creation by certutil:** If the hive dump files (e.g., `sam`, `system`, `security` or variations) are created in temp directories by certutil.exe, this provides a direct artifact. The `-split` and `-urldecode` flags are not standard certificate operations and indicate file manipulation.

6. **EID 5379 — credential manager reads coinciding with SAM dump activity:** The seven credential manager read events from SYSTEM running alongside the certutil cascade can be correlated to flag the full credential access episode.
