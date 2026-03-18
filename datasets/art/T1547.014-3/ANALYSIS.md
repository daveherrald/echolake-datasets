# T1547.014-3: Active Setup — Re-execute StubPath by Decreasing Version Number (HKCU)

## Technique Context

Active Setup triggers a component's StubPath only when the HKLM version number is higher than
the per-user copy stored under `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>`.
This test demonstrates a different abuse path: instead of writing a new malicious StubPath, it
resets the user's version counter for an existing component to `0,0,0,0` in HKCU, which causes
Active Setup to re-run the already-registered StubPath on the next trigger. The target component
is again `{C9E9A340-D1F1-11D0-821E-444553540600}` (Internet Explorer Core Fonts). After
downgrading the version, the test calls `runonce.exe /AlternateShellStartup` to force the check
immediately.

## What This Dataset Contains

**Sysmon (49 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), and EID 10 (ProcessAccess). Key process-create events:

- `whoami.exe` spawned by PowerShell — ART test framework pre-check
- `powershell.exe` (child of test framework) with command line:
  `"powershell.exe" & {Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{C9E9A340-D1F1-11D0-821E-444553540600}" -Name "Version" -Value "0,0,0,0" & $env:SYSTEMROOT\system32\runonce.exe /AlternateShellStartup}`
- `runonce.exe /AlternateShellStartup` — the Active Setup trigger

**Security (12 events):** EID 4688/4689 and EID 4703. The process tree shows `whoami.exe`,
the child `powershell.exe` with the full Set-ItemProperty command, `runonce.exe`, and an EID 4703
Token Right Adjusted event for the SYSTEM logon session.

Notably, `calc.exe` does **not** appear in the Security event log process tree, even though
`runonce.exe` executed. The existing StubPath for this component points to a legitimate payload
that did not result in a new observable process creation.

**PowerShell (38 events):** EID 4103 records `Set-ItemProperty` with the HKCU path, `Name=Version`,
`Value=0,0,0,0`. EID 4104 captures the full script block. As with other tests in this series,
the bulk of 4104 events are repetitive ART test framework boilerplate error-formatting scriptblocks.

## What This Dataset Does Not Contain (and Why)

**No payload execution telemetry** — because this test modifies the HKCU version number rather
than inserting a malicious StubPath, the component's legitimate StubPath is what executes (or the
re-check finds the HKLM StubPath already satisfied). In a real attack this same technique would
trigger whatever payload is already registered. The absence of a new process here reflects that
the existing component's StubPath did not produce an observable child process in this environment.

**No registry write Sysmon EID 13** — the Set-ItemProperty write to HKCU is not captured in the
Sysmon data because the sysmon-modular config's include-mode ProcessCreate filter does not
include a specific rule for this write path, and the registry events channel was not in scope.

**No logon-triggered telemetry** — the technique was triggered immediately via `runonce.exe`
rather than waiting for user logon.

## Assessment

This dataset captures the **setup phase** of the Active Setup version-downgrade technique with
full fidelity: the PowerShell command writing `Version=0,0,0,0` to HKCU is recorded in both
Security EID 4688 (command line) and PowerShell EID 4103 (parameter binding). The `runonce.exe`
invocation is present. However, because an innocuous payload is already registered, no malicious
child process appears. The detection value lies in the version-manipulation command itself, not
in downstream execution.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` command line with `Set-ItemProperty`
  targeting `HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\*` and setting `Version`
  to `0,0,0,0`
- **PowerShell EID 4103:** `Set-ItemProperty` parameter binding showing `Path` =
  `HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>`, `Name=Version`,
  `Value=0,0,0,0` — an explicit version-zeroing action
- **Security EID 4688 / Sysmon EID 1:** `runonce.exe /AlternateShellStartup` called immediately
  after the registry write — this sequence (version downgrade + runonce trigger) is a distinctive
  two-step pattern
- **Behavioral:** Any process writing a version value of `0,0,0,0` to HKCU Active Setup
  component entries should be treated as suspicious regardless of the writer
