# T1562.001-27: Disable or Modify Tools — Disable Windows Defender with DISM

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes using the
Deployment Image Servicing and Management (DISM) tool to remove Windows Defender as an
optional Windows feature. Unlike registry-based disabling or service termination, this
approach removes the Defender feature at the OS component level, requiring a reboot to take
full effect but producing a more durable outcome. DISM is a legitimate Windows system
administration tool, and its use for disabling Defender requires SYSTEM-level privilege.
This technique is used by some ransomware families and advanced operators who want to ensure
Defender cannot be easily re-enabled by a user or administrator after their initial access.

In this dataset, Defender is **disabled** — the technique executes without Tamper Protection
or real-time protection blocking the attempt.

## What This Dataset Contains

The dataset captures 41 events across two channels (38 PowerShell, 3 Security) spanning
approximately 3 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, domain member of
acme.local, 2026-03-17T17:35:53Z–17:35:56Z).

**Security EID 4688 — The full DISM command line is captured in process creation events.**
The ART test framework spawns `cmd.exe` with:

```
"cmd.exe" /c Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet
```

The parent process is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` running
as `NT AUTHORITY\SYSTEM` (Logon ID `0x3E7`, Mandatory Label `S-1-16-16384` — High integrity).
Two additional 4688 events capture `whoami.exe` (the ART pre- and post-execution identity
check, `"C:\Windows\system32\whoami.exe"`, parent PowerShell).

**PowerShell EID 4100 — Two error events.** Both carry the message:

```
Error Message = Exception calling "Start" with "0" argument(s): "Access is denied"
Fully Qualified Error ID = Win32Exception,Invoke-Process
```

The ART test framework `Invoke-Process` function attempted to launch `dism.exe` as a subprocess
using the `System.Diagnostics.Process` API and received `ACCESS_DENIED`. This is the
test framework-level error — the process could not be started because Defender's underlying
feature-removal APIs (called by DISM) returned a failure. The error fires twice,
corresponding to two invocation attempts in the test logic.

**PowerShell EID 4103 — One module pipeline event** showing `Write-Host` logging the error
text to the console: `ERROR: Exception calling "Start" with "0" argument(s): "Access is
denied"`.

**PowerShell EID 4104 — 35 script block events.** The substantial blocks are:

```powershell
$endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
```
```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 27 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

The remaining 4104 events are PowerShell error-formatting stubs (`Set-StrictMode -Version 1;
$_.PSMessageDetails`, etc.) generated as part of the ART error-handling pipeline. The DISM
command itself does not appear as a 4104 block because it was invoked via `cmd.exe`, not
directly from a PowerShell script block.

## What This Dataset Does Not Contain

**No Sysmon events.** The undefended dataset captures only PowerShell/Operational and
Security channels — no Sysmon data is bundled. This contrasts with the defended variant,
which includes 25 Sysmon events including EID 1 (process create for `cmd.exe`) and EID 8
(CreateRemoteThread attributed to Defender behavior monitoring intercepting the DISM
attempt). To see process tree and image load data for this technique, consult the defended
dataset (art-T1562.001-27).

**No DISM.exe process creation event.** DISM runs as a child of `cmd.exe` but neither
the Security 4688 nor the Sysmon (absent here) log captures `dism.exe` explicitly. The
`cmd.exe` event with the full DISM command line is the primary process creation artifact.

**No `cmd.exe` exit status.** Security 4689 (process exit with status code) events are
not in the bundled Security channel for this dataset. The 4100 Access Denied errors confirm
the DISM operation failed, but the numeric NT status code (`0xC0000022`) visible in the
defended variant's process exit events is not present here.

**No Windows Modules Installer / TrustedInstaller activity.** Unlike test 36
(`Disable-WindowsOptionalFeature`), DISM invoked via `cmd.exe /c Dism /online
/Disable-Feature` does not engage the full Windows Modules Installer service pipeline on
this host. No System EID 7040 or Task Scheduler events appear.

## Assessment

This dataset documents a **failed attempt** to disable Windows Defender via DISM on a host
where Defender is already disabled at the policy level. The failure is not from Tamper
Protection (which would block the operation when Defender is active) but from the DISM
feature-removal API returning `ACCESS_DENIED` — likely because the feature removal requires
conditions not met in this environment (evaluation license, already-modified component state,
or domain policy restrictions). The command reached `cmd.exe` and DISM was invoked, as
confirmed by the 4688 event. The two PowerShell 4100 error events capture the test framework
detecting the failure.

Compared to the defended dataset, this undefended run produces fewer total events (41 vs. 75
across all channels) because Sysmon is absent from the bundled data. The Security 4688
command line evidence is equivalent in both variants — the key forensic artifact (the exact
DISM command with `/FeatureName:Windows-Defender /Remove`) appears in both.

## Detection Opportunities Present in This Data

**Security EID 4688 with DISM command line.** The `cmd.exe` 4688 event contains the full
DISM invocation including `/Disable-Feature`, `/FeatureName:Windows-Defender`, and `/Remove`.
Process command line auditing capturing `cmd.exe` children with `dism` and `Disable-Feature`
in combination is a reliable indicator of this technique.

**PowerShell EID 4100 — Access Denied from `Invoke-Process`.** The ART test framework generates
a characteristic `Win32Exception,Invoke-Process` error when DISM fails. This specific error
ID does not appear in normal DISM administrative usage and marks the ART-specific invocation
path, though defenders should focus on the 4688 command line rather than test framework error
patterns when building production detections.

**PowerShell EID 4104 — Script block logging captures the ART test framework context.** The cleanup
block explicitly names `T1562.001 -TestNumbers 27`, providing unambiguous attribution in a
test environment. In a real attack, the equivalent 4104 events would contain the attacker's
own PowerShell wrapper, which may or may not name the technique directly.

**SYSTEM-context process chain.** All 4688 events show `SubjectUserSid: S-1-5-18` (SYSTEM)
with `MandatoryLabel: S-1-16-16384` (High integrity). PowerShell spawning `cmd.exe` spawning
DISM, all running as SYSTEM, with Mandatory Label `S-1-16-16384`, is not a normal
administrative pattern and warrants investigation.
