# T1218.009-2: Regsvcs/Regasm — Regsvcs Uninstall Method Call Test

## Technique Context

T1218.009 (Regsvcs/Regasm) is a defense evasion technique where attackers abuse Microsoft's .NET Services Installation Utility (RegSvcs.exe) or .NET Framework Assembly Registration Utility (RegAsm.exe) to proxy execution of malicious code. These are signed Microsoft binaries that can load and execute arbitrary .NET assemblies, making them valuable Living Off The Land Binaries (LOLBins). The technique is particularly effective because RegSvcs.exe can execute code during both installation and uninstall phases of COM+ applications, and the binaries have legitimate purposes in enterprise environments. Detection engineers typically focus on unusual command-line arguments, execution from unexpected directories, loading of unsigned assemblies, and process lineage involving these utilities.

## What This Dataset Contains

This dataset captures a complete RegSvcs.exe execution chain initiated via PowerShell. The attack begins with Security 4688 showing PowerShell spawning with a complex command line containing Base64-encoded key material: `"powershell.exe" & {$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V3E7F5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='`.

Sysmon EID 1 captures the process creation of csc.exe with command line: `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /r:System.EnterpriseServices.dll /out:C:\Windows\TEMP\T1218.009.dll /target:library /keyfile:C:\Windows\TEMP\key.snk C:\AtomicRedTeam\atomics\T1218.009\src\T1218.009.cs`, showing the compilation of a malicious .NET assembly. Multiple Sysmon EID 11 events show file creation of the key file (`C:\Windows\Temp\key.snk`) and the compiled DLL (`C:\Windows\Temp\T1218.009.dll`).

The critical RegSvcs.exe execution appears in Sysmon EID 1: `"C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe" C:\Windows\TEMP\T1218.009.dll`. Sysmon EID 7 shows RegSvcs.exe loading the malicious DLL multiple times (`C:\Windows\Temp\T1218.009.dll` with hash SHA256=3682CA769070AF5A4739BBDB7512DA46FBCBB345AB31A3DEAB29E75CEDC9A12A), confirming successful code execution. Additional file creation events show the generation of a type library (`C:\Windows\Temp\T1218.009.tlb`) and registry database updates (`C:\Windows\Registration\_RegDBWrt.clb`).

The PowerShell scriptblock in EID 4104 reveals the complete attack payload, including the assembly compilation and RegSvcs execution commands.

## What This Dataset Does Not Contain

The dataset lacks network connections that might occur if the malicious assembly performed network communication. While DNS queries are captured (EID 22 shows a query for ACME-WS02), there are no outbound network connections captured in the Sysmon data. The technique completed successfully without Windows Defender blocking it, so there are no Defender-related error messages or blocked execution events. Registry modifications that typically accompany COM+ application registration are not captured in the available event logs, as the dataset doesn't include registry monitoring events. Process injection or memory manipulation events that might occur within the RegSvcs.exe process during DLL loading are also not present, limiting visibility into the actual malicious code execution within the process space.

## Assessment

This dataset provides excellent coverage for detecting T1218.009 attacks. The combination of Security 4688 process creation events with full command lines, Sysmon EID 1 process creation, EID 7 image loads, and EID 11 file creation events creates a comprehensive detection surface. The PowerShell scriptblock logging captures the entire attack methodology, including the Base64-encoded key material and compilation process. The multiple image load events showing the same unsigned DLL being loaded repeatedly by RegSvcs.exe provide clear indicators of malicious activity. File creation events tracking the progression from key file to compiled DLL to type library offer additional detection opportunities. The process lineage from PowerShell to csc.exe to RegSvcs.exe is well-documented across multiple data sources.

## Detection Opportunities Present in This Data

1. **RegSvcs.exe execution with unsigned DLL loading** - Monitor Sysmon EID 7 for RegSvcs.exe loading unsigned DLLs, especially from temporary directories like `C:\Windows\Temp\`

2. **PowerShell command lines containing RegSvcs.exe calls** - Detect Security 4688 or PowerShell scriptblocks (EID 4104) referencing `regsvcs.exe` with DLL paths

3. **Base64-encoded content in PowerShell combined with .NET compilation** - Alert on scriptblocks containing large Base64 strings alongside `csc.exe` or compiler references

4. **Suspicious process chain: PowerShell → csc.exe → RegSvcs.exe** - Track process lineage in Sysmon EID 1 showing this specific execution flow

5. **File creation of DLL in temp directories followed by RegSvcs.exe execution** - Correlate Sysmon EID 11 file creation events with subsequent RegSvcs.exe process creation targeting the same file

6. **RegSvcs.exe loading the same DLL multiple times** - Monitor for unusual patterns in EID 7 where RegSvcs.exe repeatedly loads the same unsigned assembly

7. **Command line compilation with System.EnterpriseServices.dll reference** - Detect csc.exe executions with `/r:System.EnterpriseServices.dll` parameter indicating COM+ component creation

8. **Type library (.tlb) file creation in temporary directories** - Monitor EID 11 for .tlb file creation as a secondary indicator of COM+ registration activity
