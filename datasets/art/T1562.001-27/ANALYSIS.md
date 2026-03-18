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

## What This Dataset Contains

The dataset captures 25 Sysmon events, 9 Security events, and 41 PowerShell events spanning
approximately 5 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The attack command is captured in Security 4688. The parent PowerShell (ART test framework)
spawns `cmd.exe` with:

```
"cmd.exe" /c Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet
```

The Sysmon EID 1 for the `cmd.exe` spawn is present. A `whoami.exe` pre-execution check
appears (Sysmon EID 1, Security 4688). This dataset includes a notable Sysmon EID 8
(CreateRemoteThread detected):

```
RuleName: technique_id=T1055,technique_name=Process Injection
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetImage: <unknown process>
SourceProcessId: 2720
TargetProcessId: 5696
NewThreadId: 1264
```

The target process is listed as `<unknown process>` — a brief process that terminated
before Sysmon could query its image path. This is consistent with Defender's behavior when
blocking or intercepting certain operations; AMSI or Defender's behavior monitoring engine
may inject into or terminate short-lived processes.

**The `cmd.exe` process exited with status 0xC0000022** (ACCESS_DENIED). DISM attempted
to disable the Windows-Defender feature and was blocked. Status 0xC0000022 is the NT status
code for access denied, returned by the feature management APIs when Tamper Protection
or system integrity protections prevent the removal.

## What This Dataset Does Not Contain (and Why)

**No DISM.exe process in Sysmon EID 1.** The sysmon-modular include-mode configuration
does not have an include rule matching `dism.exe` by name. DISM runs as a child of
`cmd.exe` but does not appear in the Sysmon process create log. It does appear in Security
4689 (exit events are not present for `dism.exe` specifically in the bundled data, but
the exit code from `cmd.exe` captures the outcome). Security 4688 captures the cmd.exe
invocation with the full DISM command line.

**No successful feature removal.** The 0xC0000022 exit code confirms Defender was not
removed. Windows Defender's Tamper Protection and/or Windows Component Based Servicing
protections blocked the DISM operation. The feature remains installed.

**No PowerShell 4104 script block for the DISM command.** The DISM invocation is
constructed as a `cmd.exe` argument and dispatched via Windows Command Processor, not
as a PowerShell script block. The 41 PowerShell events are entirely the test framework boilerplate
(`Set-ExecutionPolicy` in 4103, error-handling closures in 4104).

**No System or Setup log events.** DISM operations log to the Windows Setup log and
CBS log, neither of which is in the collection scope.

## Assessment

The test executed and was blocked. The telemetry captures the attempt faithfully: the full
DISM command line is in Security 4688, the access denied exit code (0xC0000022) is in
Security 4689, and the anomalous CreateRemoteThread event suggests Defender's behavior
monitoring actively intervened during the attempt. This dataset is valuable for training
detection on the attempt pattern and on Defender's characteristic blocking indicators.

## Detection Opportunities Present in This Data

- **Security 4688 command line containing `Dism` with `/Disable-Feature` and
  `FeatureName:Windows-Defender`**: This combination is unambiguous and has no legitimate
  use in operational environments. The `/Remove` flag signals intent to permanently
  excise the component.

- **Exit code 0xC0000022 from cmd.exe**: A DISM invocation that exits with ACCESS_DENIED
  confirms Defender Tamper Protection is functioning. This is a useful indicator of a
  blocked defense evasion attempt, distinct from a successful one.

- **Sysmon EID 8 (CreateRemoteThread) with `<unknown process>` target**: This pattern —
  PowerShell injecting a thread into an ephemeral process during a Defender interaction —
  is worth correlating with the DISM activity in the same timeframe. It indicates active
  behavioral monitoring by Defender during the attack.

- **Parent-child chain**: `powershell.exe` → `cmd.exe` → DISM command with Defender
  feature flags is a specific, high-value process lineage pattern.
