# T1059.001-17: PowerShell — Obfuscated Command Execution via Base64-Encoded IEX

## Technique Context

T1059.001 PowerShell execution spans a wide range of obfuscation depths, from plaintext commands to heavily layered encoding. This test targets a common middle ground: invoking PowerShell through cmd.exe with the `-e` flag (shorthand for `-EncodedCommand`) where the Base64 payload decodes to an obfuscated `Invoke-Expression` (IEX) call using string manipulation and dynamic cmdlet resolution. The technique encodes the command once and uses character array manipulation or string concatenation within the encoded payload to avoid direct `IEX` string detection.

Specifically, the pattern demonstrated here uses `gcm` (shorthand for `Get-Command`), a format string with a placeholder (`ie{0}` formatted with `'x'`), and a dynamically constructed string to produce `iex` at runtime without the literal string `iex` or `Invoke-Expression` appearing in the encoded command or its immediate decoded form. This approach targets rules that check for specific keywords in decoded script block content while missing the dynamic construction pattern.

The cmd.exe intermediary is deliberate: it adds a process layer that some detection tools anchor on the PowerShell command line itself. An analyst looking only at the `powershell.exe` process's command line sees Base64; looking at the parent `cmd.exe` sees the full `powershell.exe -e <base64>` invocation. The full attack chain requires correlating both process creation events.

## What This Dataset Contains

The dataset spans five seconds (2026-03-14T23:19:05Z to 23:19:10Z) and records 142 events across three channels: Sysmon (28), PowerShell (109), and Security (5).

**Security EID 4688** captures five process creation events. The most valuable are:

```
"cmd.exe" /c powershell.exe -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcA...
```

and

```
powershell.exe  -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBl...
```

The first is cmd.exe launching PowerShell with `-e` (note the double space before the Base64, an artifact of the ART test framework command construction). The second is the PowerShell process with the actual Base64 payload. Decoding the Base64 string `JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkA...` yields (in UTF-16LE):

```powershell
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"e"+"llo"...)
```

This uses `gcm` to get the `iex` cmdlet by formatting the string `ie{0}` with `x`, then calls it on a string assembled from concatenated fragments. The `Write-Host` payload is similarly fragmented to avoid direct string matching.

**Sysmon EID 1** captures the same process creation events with rule tagging. The cmd.exe event fires `technique_id=T1059.003`. The child PowerShell process fires `technique_id=T1059.001,technique_name=PowerShell`. The `whoami.exe` events fire `technique_id=T1033`.

**Sysmon EID 10 (ProcessAccess)** shows 4 events. The test framework opens `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`. Two distinct cmd.exe access events appear (the actual attack command and the cleanup empty cmd.exe) — consistent with the ART test framework managing both invocations.

**Sysmon EID 7 (ImageLoad)** contributes 15 events including the .NET DLL chain across the test framework and child PowerShell processes.

**Sysmon EID 17 (PipeCreate)** shows 2 events — the test framework and child PowerShell pipes.

**Sysmon EID 11 (FileCreate)** records 2 events for PowerShell profile initialization files.

**PowerShell EID 4104** contributes 104 events. Crucially, script block logging captures the decoded content of the `-e` payload. When the obfuscated `(gcm ('ie{0}' -f 'x'))` executes, PowerShell's script block engine records what it actually evaluates — meaning the `Write-Host` call appears decoded in an EID 4104 event, even though the command line shows only Base64. **EID 4103** (module invocation logging) contributes 5 events, recording cmdlet execution with parameters for the actual commands called.

Compared to the defended version (37 sysmon, 14 security, 40 PowerShell), the undefended dataset shows slightly fewer Sysmon events (28 vs. 37) and more PowerShell events (109 vs. 40). The higher PowerShell count reflects the successful execution of the obfuscated payload generating additional EID 4104 blocks.

## What This Dataset Does Not Contain

No network events appear — this test does not initiate network connections.

No registry events — the technique is purely command-line based.

The specific output of `Write-Host` is not captured in any event — console output is not logged by Windows telemetry.

The full Base64 string in the command line is truncated in the Security EID 4688 samples. The complete Base64 payload is present in the full raw events but requires reading the untruncated `CommandLine` field.

## Assessment

This dataset is well-suited for testing the depth of coverage of obfuscated PowerShell detections. It provides three distinct detection opportunities at different sophistication levels: the Base64 command line (low bar, easily automated), the decoded script block content via EID 4104 (medium bar, requires PowerShell logging), and the dynamic IEX construction pattern `(gcm ('ie{0}' -f 'x'))` (high bar, requires semantic analysis). The comparison with the defended version confirms that this obfuscation pattern doesn't trigger Defender, making it relevant for environments relying primarily on Defender for protection — coverage must come from logging-based detections.

## Detection Opportunities Present in This Data

1. **PowerShell with `-e` or `-E` followed by Base64 content spawned by cmd.exe**: Security EID 4688 captures `cmd.exe /c powershell.exe -e <base64>`. The pattern of cmd.exe launching PowerShell with short-form encoded command parameters identifies a scripted execution layer designed to obscure the payload.

2. **Sysmon EID 1 rule tag technique_id=T1059.001 on the child PowerShell process**: The spawned PowerShell process fires the T1059.001 rule. Combining this rule tag with parent process being `cmd.exe` (rather than an interactive user session) narrows to automated execution.

3. **EID 4104 ScriptBlockText containing `gcm`, format string IEX construction, or string concatenation for cmdlet resolution**: The decoded payload uses `(gcm ('ie{0}' -f 'x'))` to dynamically construct `iex`. Pattern matching for `gcm` combined with string format operators in script blocks, or string concatenation producing known cmdlet names like `Invoke-Expression`, catches this obfuscation layer.

4. **Temporal correlation of EID 4688 Base64 command line with EID 4104 decoded content**: The same process ID appears in both the Security EID 4688 event (encoded command line) and the PowerShell EID 4104 events (decoded execution). Linking these by process ID or timing reveals the encoding/decoding relationship and defeats the obfuscation.

5. **EID 4103 (Module invocation logging) for dynamically resolved cmdlets**: When PowerShell resolves and calls `iex` via the dynamic `gcm` method, EID 4103 records the cmdlet invocation with the actual resolved function name. Module logging provides ground truth on what was executed even when the script block shows only the dynamic resolution code.

6. **cmd.exe spawning PowerShell with `-e` (double space)**: The double space before the Base64 payload (`-e  JgAg...`) is an artifact of specific command construction patterns. While not universally present, this spacing artifact in conjunction with other indicators can help identify specific tooling or test framework variants.
