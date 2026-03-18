# T1202-4: Indirect Command Execution — ScriptRunner.exe

## Technique Context

T1202 (Indirect Command Execution) encompasses the use of trusted, signed Windows binaries to execute arbitrary commands in a way that makes the resulting process tree appear more legitimate. `ScriptRunner.exe` is a Microsoft-signed binary located in `C:\Windows\System32\` that was originally designed to execute scripts in Microsoft Application Virtualization (App-V) environments. Its `-appvscript` parameter accepts an executable path, making it usable as a signed proxy launcher. Since ScriptRunner.exe is a Microsoft binary in System32, it passes most application whitelisting policies, and its unusual name may not trigger detections focused on more common LOLBins like `mshta.exe` or `regsvr32.exe`.

## What This Dataset Contains

This dataset captures a complete and successful ScriptRunner.exe proxy execution. Security EID 4688 documents the full process chain:

1. PowerShell (PID 0x476c — test framework parent) spawns PowerShell (PID 0x404c) with command line `"powershell.exe" & {Scriptrunner.exe -appvscript "C:\Windows\System32\calc.exe"}`
2. PowerShell (0x404c) spawns `ScriptRunner.exe` (PID 0x4560) with `"C:\Windows\system32\ScriptRunner.exe" -appvscript C:\Windows\System32\calc.exe`
3. ScriptRunner.exe (0x4560) spawns `calc.exe` (PID 0x4634) successfully

All four process creations appear in Security EID 4688 with the creator process name correctly attributed, making the process lineage fully reconstructable. Sysmon EID 1 also captures the process creations; notably, Sysmon's rule engine tags the PowerShell process (that calls ScriptRunner) with `RuleName: technique_id=T1218,technique_name=System Binary Proxy Execution`, correctly categorizing the behavior even before the ScriptRunner.exe process itself is created.

The Sysmon channel totals 48 events: 32 EID 7 (DLL loads), 6 EID 10 (process access), 5 EID 1 (process creation), 3 EID 17 (named pipe), and 2 EID 11 (file creation). The heavy DLL load count reflects .NET runtime initialization — ScriptRunner.exe triggers loading of the .NET CLR, mscoreei.dll, and several PowerShell automation libraries as part of the App-V script execution subsystem. Sysmon EID 10 shows PowerShell accessing both ScriptRunner.exe and calc.exe with full access rights.

The PowerShell channel captures 111 events, predominantly test framework boilerplate. The key script block visible in the sample set is `& {Scriptrunner.exe -appvscript "C:\Windows\System32\calc.exe"}`, confirming the specific ART command used.

## What This Dataset Does Not Contain

There are no network activity events — ScriptRunner.exe executing calc.exe is an entirely local operation. No registry modifications (Sysmon EID 13) are present, consistent with a technique that requires no persistence mechanism. No Application channel events appear, confirming that Defender did not flag this behavior even when active (the technique succeeded in the defended environment as well).

The dataset does not include Sysmon EID 1 for calc.exe itself in the sampled events, though the Security EID 4688 confirms its creation. Defenders relying solely on Sysmon with restrictive process inclusion rules may miss the final payload launch if calc.exe (or any "known-good" binary used as a stand-in payload) is filtered.

## Assessment

The defended and undefended datasets for this technique are similar in content because Defender does not block ScriptRunner.exe-based proxy execution. The defended dataset has 56 Sysmon events vs. 48 here, and 38 vs. 111 PowerShell events — the PowerShell difference again reflects the test framework executing more completely without AMSI interruption. The technique-specific artifacts (ScriptRunner.exe with `-appvscript` argument, the resulting calc.exe as a child) are present in both.

ScriptRunner.exe is an uncommon LOLBin compared to mshta.exe or regsvr32.exe. In a real environment, a ScriptRunner.exe process creation outside of an App-V deployment should be immediately suspicious. The `-appvscript` parameter pointing to a system binary in `System32\` is the key signal — in a legitimate App-V deployment, this would point to an App-V application executable, not a standard system binary.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: `ScriptRunner.exe` process creation with `-appvscript` argument — this binary has no legitimate use case outside of App-V environments, so any invocation on a non-App-V workstation is anomalous
- **Security EID 4688**: Process lineage `powershell.exe` → `ScriptRunner.exe` → `<payload>` is the core detection pattern; the parent-child relationship is fully captured with creator process names
- **PowerShell EID 4104**: Script block content `Scriptrunner.exe -appvscript` appearing in script block logs is a high-confidence detection artifact, as this exact string would not appear in legitimate automation
- **Sysmon EID 1 (tagged)**: Sysmon's rule-based tagging of `technique_id=T1218,technique_name=System Binary Proxy Execution` on the PowerShell invocation event demonstrates that existing Sysmon rule sets (sysmon-modular) already detect this technique's behavioral signature
- **Sysmon EID 7**: .NET CLR DLLs loading into `ScriptRunner.exe` (a normally lightweight binary) may be an anomaly indicator when ScriptRunner is used as a proxy for .NET-based payloads
