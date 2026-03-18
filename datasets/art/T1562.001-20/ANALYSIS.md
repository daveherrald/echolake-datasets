# T1562.001-20: Disable or Modify Tools — Remove Windows Defender Definition Files

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes degrading the
effectiveness of security tools short of disabling them entirely. Removing Windows Defender's
signature definition files leaves the engine running but functionally blind to known malware.
The built-in `MpCmdRun.exe` utility with the `-RemoveDefinitions` flag provides a signed,
Microsoft-provided mechanism for this operation. Attackers use this approach because it
avoids directly stopping the Defender service — a more easily detected action — while still
achieving the goal of eliminating detection capability for signature-based threats.

## What This Dataset Contains

The dataset captures 31 Sysmon events, 12 Security events, and 34 PowerShell events spanning
approximately 6 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The process chain is the primary artifact. A parent PowerShell process invokes a child
PowerShell via the ART test framework, which in turn spawns `cmd.exe` and then `MpCmdRun.exe`:

From Security 4688:
```
New Process Name:  C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c "C:\Program Files\Windows Defender\MpCmdRun.exe"
                      -RemoveDefinitions -All
```
```
New Process Name:  C:\Program Files\Windows Defender\MpCmdRun.exe
Process Command Line: "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

Sysmon EID 1 captures `cmd.exe` with `RuleName: technique_id=T1059.003,technique_name=Windows
Command Shell` — the include-mode filter matched the `cmd.exe` pattern in the MpCmdRun
invocation context. The parent PowerShell is captured via the T1059.001 rule.

The standard ART test framework preamble is present: `Set-ExecutionPolicy Bypass` (4103), `whoami.exe`
process creation (Sysmon EID 1, Security 4688), and PowerShell startup profile file creation.

**MpCmdRun.exe exited with status 0x2** (and cmd.exe inherited the same exit code), indicating
the definition removal command failed. The parent PowerShell exited cleanly (0x0). This
failure is consistent with Windows Defender's Tamper Protection, which blocks modification
of definition files even by MpCmdRun.exe itself when Tamper Protection is enabled.

## What This Dataset Does Not Contain (and Why)

**No successful definition removal.** The exit code 0x2 from MpCmdRun.exe indicates failure.
With Tamper Protection active, the definitions were not removed. This dataset captures the
attempt and its blocked outcome, not successful impairment. No Defender Application log
entries confirming definition removal appear.

**No MpCmdRun.exe in Sysmon EID 1.** The sysmon-modular include-mode ProcessCreate filter
did not match `MpCmdRun.exe` by name. The process appears in Security 4688 (which provides
full coverage via audit policy) but not in Sysmon. This illustrates the complementary nature
of the two sources.

**No PowerShell 4104 script block for the attack payload.** The ART test framework for this test
uses `cmd.exe` as the immediate child, so the actual MpCmdRun command is in the `cmd.exe`
argument rather than a PowerShell script block. The 4104 events present are entirely
boilerplate internal PowerShell error-handling closures.

**No registry audit events.** Object access auditing is disabled; no Security 4657 entries
for any Defender configuration keys appear.

## Assessment

The test executed and was blocked by Windows Defender's Tamper Protection. The telemetry
accurately captures this outcome: the command was attempted (visible in 4688 and Sysmon EID 1
on cmd.exe), the exit code confirms failure (0x2), and no Defender Application log events
confirming definition removal are present. This dataset is valuable for training detection
on the attempt pattern even when the operation is blocked.

## Detection Opportunities Present in This Data

- **Security 4688 command line containing `-RemoveDefinitions`**: The full command line is
  captured in the Security log. Alerting on `MpCmdRun.exe` invocations with `-RemoveDefinitions`
  is a reliable indicator; this flag has no legitimate administrative use in most environments.

- **Process lineage**: `powershell.exe` → `cmd.exe` → `MpCmdRun.exe` with `-RemoveDefinitions`
  arguments is the specific chain captured here. Parent process awareness is key to
  distinguishing this from scheduled Defender updates.

- **Sysmon EID 1 on cmd.exe**: The cmd.exe process create is captured because the include
  rules matched the process. The command line argument containing `MpCmdRun.exe -RemoveDefinitions`
  is visible directly.

- **Exit code 0x2**: A failed MpCmdRun.exe invocation with this specific flag and this exit
  code is itself a detection opportunity — it indicates a blocked tamper attempt.
