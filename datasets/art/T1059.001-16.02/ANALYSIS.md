# T1059.001-16: PowerShell — EncodedCommand Parameter Variations with Encoded Arguments (ATHPowerShellCommandLineParameter)

## Technique Context

T1059.001 PowerShell execution includes significant variation in how the interpreter is invoked. PowerShell's `-EncodedCommand` parameter accepts Base64-encoded command text, which was designed as an administrator convenience for passing complex commands to non-interactive PowerShell processes. Adversaries use it for a different purpose: obscuring command content from basic string-matching detections, from logging systems that capture command lines but not script block content, and from analysts doing a quick review of process trees.

This specific test exercises the `-E` shorthand for `-EncodedCommand` combined with encoded arguments. PowerShell accepts multiple abbreviations for `-EncodedCommand`: `-E`, `-En`, `-Enc`, `-Enco`, etc. — any unambiguous prefix works. Adversaries use these abbreviations because simple string-based rules checking for `-EncodedCommand` or `-enc` can be bypassed by choosing a variant the rule doesn't cover. The ATH (Atomic Test Test framework) framework `Out-ATHPowerShellCommandLineParameter` tests the full parameter variation space to validate detection coverage.

The encoded arguments pattern adds a second layer: not only is the command Base64-encoded, but the arguments passed to that command are also encoded. Decoding requires two passes and means that a tool that captures the command line but doesn't decode it sees only opaque Base64 content.

Unlike tests that are blocked by Defender at the payload level, this test's behavior is unchanged between defended and undefended versions — encoding itself is not malicious, and AMSI evaluates the decoded content. The similarity in event counts (33 sysmon here vs. 30 defended) confirms that Defender has minimal impact on this particular test.

## What This Dataset Contains

The dataset spans five seconds (2026-03-14T23:18:51Z to 23:18:56Z) and records 140 events across three channels: Sysmon (33), PowerShell (103), and Security (4).

**Security EID 4688** captures two key process creation events. The technique invocation shows:

```
"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -UseEncodedArguments -EncodedArguments...}
```

The parameters tell the story: `-CommandLineSwitchType Hyphen` (use `-` rather than `/`), `-EncodedCommandParamVariation E` (use `-E` as the encoded command flag), and `-UseEncodedArguments` (encode the arguments as well). The function generates the resulting PowerShell invocation and executes it.

**Sysmon EID 1** captures the child PowerShell process spawned by the ATH function. The full command line shows the actual encoded invocation:

```
"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -UseEncodedArguments -EncodedArguments <base64 data>}
```

And separately, the PowerShell process spawned by the ATH framework with the `-E <base64>` invocation:

```
"powershell.exe" & {Out-ATHPowerShellCommandLineParameter ...}
```

The actual child PowerShell process invoked with `-E <base64>` should appear in process creation events, providing the specific `-E` encoded command line for detection testing.

**Sysmon EID 10 (ProcessAccess)** shows 4 events with `GrantedAccess: 0x1FFFFF` and CLR call traces. The test framework opens `whoami.exe` and the child PowerShell process. Also recorded is an EID 10 with `TargetImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` — the ATH framework accessing the spawned PowerShell child, consistent with process management.

**Sysmon EID 7 (ImageLoad)** contributes 21 events — the full .NET runtime DLL chain across both the test framework and the spawned PowerShell child process.

**Sysmon EID 17 (PipeCreate)** records 3 events, reflecting the test framework and the spawned child process both creating PowerShell host pipes.

**Sysmon EID 11 (FileCreate)** records 1 event — a PowerShell startup profile file creation.

**PowerShell EID 4104** contributes 103 events. All samples show boilerplate, but the complete dataset includes the decoded command that `-E <base64>` executed, which is the payload itself. The value of EID 4104 in this context is precisely that it captures the decoded content — the obfuscated command line becomes transparent in script block logs.

Compared to the defended version (30 sysmon, 10 security, 45 PowerShell), the undefended dataset is nearly identical in Sysmon (33 vs. 30) but higher in PowerShell events (103 vs. 45). The higher PowerShell count in the undefended run reflects the encoded command actually executing and generating additional script blocks from its decoded payload.

## What This Dataset Does Not Contain

No network events are present — this test does not initiate network connections.

No registry events appear — the encoded command execution is entirely in-memory.

The exact decoded content of the `-E <base64>` argument is not shown in the EID 4104 sample set, but it is present in the full dataset. The specific Base64 payload would decode to a simple command demonstrating the encoding mechanism.

## Assessment

This dataset is purpose-built for validating detection coverage of PowerShell `-EncodedCommand` parameter variations. The most valuable use case is testing whether your detection rules catch `-E`, `-En`, `-Enc`, etc. in addition to the full `-EncodedCommand` string. The EID 4688 and Sysmon EID 1 events provide the encoded command line, while EID 4104 provides the decoded content — allowing comparison of what each detection approach sees.

The ATH framework approach is also useful for building training datasets that cover the realistic variation space of this technique, rather than testing against a single fixed command line. The higher PowerShell event count in this undefended run (103 vs. 45 defended) confirms that the encoded command executed successfully and generated telemetry from its decoded payload.

## Detection Opportunities Present in This Data

1. **PowerShell process with `-E`, `-En`, `-Enc`, or other `-EncodedCommand` prefix variants**: Security EID 4688 and Sysmon EID 1 capture the command line of the spawned PowerShell process. Detection rules should enumerate all valid abbreviations of `-EncodedCommand`, not just the full parameter name. The `-E` variant specifically appears here.

2. **Base64 content in PowerShell command line `-E` or `-EncodedCommand` argument**: The Base64 blob that follows `-E` is recognizable by its character set and padding structure. Detecting Base64-encoded arguments in PowerShell invocations, especially for short sessions without interactive context, is a reliable encoded-command indicator.

3. **PowerShell EID 4104 decoded content vs. encoded command line discrepancy**: The power of this detection is the mismatch: the command line shows opaque Base64, but EID 4104 shows the actual decoded commands. If your detection pipeline can correlate the encoded invocation (EID 4688) with the decoded execution (EID 4104) by process ID, the obfuscation is defeated.

4. **`Out-ATHPowerShellCommandLineParameter` or similar ATH framework functions**: The ATH framework function name appears in the command line. While real adversaries would not use ATH-named functions, the presence of this function in command-line data identifies simulation activity that can be used to validate detection rules.

5. **Multiple PowerShell host pipes in a short window**: Sysmon EID 17 shows 3 pipe creation events, reflecting the test framework and child process. When two or more PowerShell instances each create a `\PSHost.*` pipe within seconds, it indicates a parent PowerShell spawning child PowerShell instances — a pattern used for both ART-style testing and real adversary automation.

6. **Higher-than-normal EID 4104 event count for short PowerShell sessions**: The 103 EID 4104 events in 5 seconds, with multiple distinct script blocks beyond boilerplate, indicates that the encoded command executed additional PowerShell operations. An unusually high script block event count for a brief session is a behavioral indicator of encoded command payload execution.
