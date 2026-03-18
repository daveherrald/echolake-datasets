# T1562.001-14: Disable or Modify Tools — AMSI Bypass (Remove AMSI Provider Registry Key)

## Technique Context

T1562.001 (Disable or Modify Tools) includes bypassing AMSI by removing its provider registration from the Windows registry. The Windows Defender AMSI provider is registered at:
```
HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}
```

Deleting this registry key removes Defender's AMSI provider from the system-wide registration. When AMSI initializes a scan session, it queries this registry path to find registered providers. With the key absent, AMSI loads with no providers and `AmsiScanBuffer` calls return clean results for all content regardless of what is passed to them.

Unlike the in-memory InitFailed bypass (T1562.001-13), this is a persistent, system-wide change. It survives process restarts and affects all scripting hosts on the system — not just the PowerShell process that performed the deletion. The change persists until Windows Defender repair, a system restore, or manual re-registration of the provider.

The ART test executes:
```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse
```

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-17 17:34:31–17:34:37 UTC) and contains 99 PowerShell events, 3 Security events, 1 Sysmon event, and 1 Application event.

The registry deletion command is captured in Security EID 4688:
```
"powershell.exe" & {Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse}
```

Security EID 4688 records 3 process creation events: `whoami.exe` (pre-check), the removal `powershell.exe` with the full `Remove-Item` command line, and a second `whoami.exe` (post-check). All run as `NT AUTHORITY\SYSTEM`.

**Application EID 15**: One Application log event records `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`. This event is written by the Windows Security Center as Defender's provider status changes following the registry deletion. The presence of this event confirms the AMSI provider deletion was registered by the operating system's security subsystem.

**Sysmon EID 3** (NetworkConnect) from `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` — the Defender engine process. This network connection event reflects MsMpEng connecting to Defender's cloud services, likely as part of its response to the registry change or as a routine telemetry/update check. The connection is from MsMpEng, not from the attacking process.

The PowerShell events are 97 EID 4104 (script block logging) and 2 EID 4103 (module logging). Unlike the InitFailed bypass, **the `Remove-Item` payload does appear in EID 4104 script block logging**. This is because the registry deletion operates via a named PowerShell cmdlet (`Remove-Item`) rather than via in-memory reflection — AMSI scanning is active when the script runs, and AMSI logs it. The bypass only takes effect for subsequent processes after the registry key is removed.

The 2 EID 4103 events record `CommandInvocation(Set-ExecutionPolicy)` with `ExecutionPolicy: Bypass` — the standard ART test framework preamble.

## What This Dataset Does Not Contain

No Sysmon EID 12 or 13 (Registry events) for the key deletion. Registry deletion via `Remove-Item` on an HKLM key modifies the registry, but Sysmon's registry monitoring is configured with include-mode rules that did not match this specific AMSI provider key path. The deletion is visible in other sources (Security 4688 command line, PowerShell 4104) but not as a discrete Sysmon registry event.

No Security EID 4657 (Registry object access audit). Registry object access auditing is not enabled, so the deletion itself does not generate a Security log registry event.

No Sysmon EID 1 for the attack PowerShell or `whoami.exe`. This test ran in a window where Sysmon was either in a degraded state (following the T1562.001-11 driver unload earlier in the run) or the ProcessCreate filter did not fire. The Sysmon EID 3 from MsMpEng is the only Sysmon event present — process creation events are absent.

No Security EID 4688 for `whoami.exe` process exits or token adjustments. The Security channel captured only the 3 EID 4688 process creation events.

Compared to the defended variant (36 Sysmon, 10 Security, 38 PowerShell, 1 Application), this undefended run has fewer Sysmon events (1 vs 36) and more PowerShell events (99 vs 38). The absence of Sysmon process creation events here is likely due to the Sysmon driver state, not a configuration difference.

## Assessment

The registry-based AMSI bypass produces better telemetry than the in-memory InitFailed bypass because the `Remove-Item` cmdlet is logged by AMSI itself before the bypass takes effect. The full AMSI provider GUID `{2781761E-28E0-4109-99FE-B9D127C57AFE}` appears in the Security 4688 command line and — in the defended variant — in PowerShell 4104 script block logging.

The Application EID 15 event is an underappreciated artifact: Windows Security Center's status update event fires when the AMSI provider registration changes. This event is generated by a completely independent Windows subsystem (Security Center) and cannot be suppressed by manipulating the AMSI layer itself — making it a reliable side-effect indicator of this specific bypass method.

The persistent nature of this bypass (system-wide, survives reboots) makes it more operationally significant than the InitFailed bypass. Detection of the attempt is critical because a successful execution leaves the system AMSI-blind until remediated.

## Detection Opportunities Present in This Data

**Security EID 4688 command line**: `Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse` is fully captured. The AMSI provider GUID `{2781761E-28E0-4109-99FE-B9D127C57AFE}` in a `Remove-Item` or `reg delete` command is a high-precision indicator with no legitimate use case.

**Application EID 15** `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`: While this message sounds benign, its occurrence as an isolated event following suspicious PowerShell activity is a contextual indicator. Monitoring Application EID 15 for Defender status changes, especially when correlated with AMSI-related PowerShell activity, can detect this bypass variant.

**Sysmon EID 3 from MsMpEng**: The Defender engine's network connection following a registry modification is a behavioral correlation opportunity. MsMpEng connecting to cloud services immediately after an AMSI-related registry change suggests a threat response or telemetry upload — both of which indicate the bypass attempt was registered by Defender's kernel components.

**PowerShell EID 4104 containing the AMSI GUID**: In environments where Sysmon is in a healthy state, the script block logging captures `{2781761E-28E0-4109-99FE-B9D127C57AFE}` in the `Remove-Item` scriptblock. String matching for this GUID in script block logging is a reliable, low-noise indicator.

**Registry monitoring**: Any registry monitor watching `HKLM:\SOFTWARE\Microsoft\AMSI\Providers\` for key deletions will catch this technique directly. The key path is known and the deletion is unambiguous.
