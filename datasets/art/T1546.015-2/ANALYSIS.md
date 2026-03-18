# T1546.015-2: Component Object Model Hijacking — PowerShell Execute COM Object

## Technique Context

T1546.015 (Component Object Model Hijacking) exploits the Windows COM registry resolution order. COM objects are looked up in HKCU before HKLM; by registering a malicious InprocServer32 in HKCU for a CLSID that a privileged application also uses, an unprivileged attacker can redirect that application's COM activation to attacker-controlled code. Beyond the registration abuse, COM objects can also be instantiated directly from PowerShell and used to execute code under a different process context — a technique that blends legitimate COM usage with execution chains that bypass typical scripting controls. This test demonstrates the latter: using `[activator]::CreateInstance` with `Shell.Windows` CLSID to call `ShellExecute` and launch a process, effectively executing through the Windows Shell COM server.

## What This Dataset Contains

The central evidence is in PowerShell script block logging (Event ID 4104). Two script blocks capture the full payload:

```powershell
$o= [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39"))
$item = $o.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
```

The CLSID `9BA05972-F6A8-11CF-A442-00A0C90A8F39` is the Windows Shell (`Shell.Windows`) COM object. The `ShellExecute` call launches `cmd.exe /c calc.exe`.

Security 4688 records confirm a PowerShell process was spawned with this script block as its command line argument, and a second process creation shows the `cmd.exe` or `calc.exe` resulting from the COM `ShellExecute` call.

Sysmon Event ID 1 captures `powershell.exe` (tagged `T1083`/File Discovery due to rule match on the PS host) and `whoami.exe` (tagged T1033). Sysmon Event ID 7 shows .NET and CLR DLL loads into PowerShell, consistent with COM activation. Event ID 10 shows PowerShell accessing the child process memory space.

## What This Dataset Does Not Contain

- **No registry writes**: this test does not perform HKCU COM hijacking by registering a malicious InprocServer32. It demonstrates COM object invocation for execution, not the persistence registration path. Sysmon Event ID 13 is absent.
- **No COM DLL loaded from an unexpected path**: the COM activation goes through the system `Shell.Windows` object, so no malicious DLL appears on disk or in image load events.
- **No Sysmon Event ID 12/13 for CLSID registration**: because no registry modifications are made, registry-based COM hijack detections will not fire.
- The Security channel contains only 5 events (2 process creations, 3 terminations) — the smallest security log in this series. The test framework did not generate 4703 token events, suggesting the execution path was more contained.
- The PowerShell channel, while containing the key script blocks, is also surrounded by the standard test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy -Bypass`).

## Assessment

This is primarily a PowerShell-based execution detection dataset, not a persistence detection dataset. Its value lies in the script block logging evidence of COM object instantiation via `GetTypeFromCLSID` and the `ShellExecute` call chain. Rules looking for COM CLSID manipulation via `[activator]::CreateInstance` or `GetTypeFromCLSID` in PowerShell would fire correctly here. It does not cover the registry hijacking path (HKCU InprocServer32 writes) that is the more dangerous persistence variant. Combining this dataset with T1546.015-3 and T1546.015-4 provides broader coverage of the COM hijacking technique space.

## Detection Opportunities Present in This Data

1. **PowerShell Event ID 4104 — `GetTypeFromCLSID` or `[activator]::CreateInstance` usage**: These .NET methods used to instantiate COM objects from known CLSIDs in script blocks are suspicious when followed by method calls like `ShellExecute`, `Exec`, or similar execution primitives.
2. **PowerShell Event ID 4104 — `ShellExecute` invoked through a COM object**: COM-mediated `ShellExecute` calls that launch shells or interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`) are high-suspicion behaviors.
3. **PowerShell Event ID 4104 — Shell.Windows CLSID (`9BA05972-...`)**: The specific `Shell.Windows` CLSID appears in multiple known LOLBin and COM execution techniques. Alerting on its instantiation in PowerShell outside of known administrative tooling is appropriate.
4. **Security 4688 — process spawn chain from PowerShell without a visible direct command line for `cmd.exe`**: When `cmd.exe /c calc.exe` (or similar) appears as a child process of a PowerShell session but the PowerShell command line does not explicitly mention `cmd.exe`, the COM-mediated execution path is implied.
5. **Sysmon Event ID 7 — CLR/MSCOREE loads followed by unusual process access (Event ID 10)**: The combination of .NET initialization DLLs loading into PowerShell and subsequent cross-process access events suggests in-process COM activation with potential process injection characteristics.
