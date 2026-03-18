# T1218-15: System Binary Proxy Execution — LOLBAS Msedge to Spawn Process

## Technique Context

T1218 System Binary Proxy Execution involves abusing legitimate, signed system binaries to execute malicious code or bypass application controls. The Edge browser executable (msedge.exe) represents a particularly interesting LOLBAS (Living Off The Land Binary) because it accepts command-line parameters that can launch arbitrary processes. The `--gpu-launcher` parameter in Microsoft Edge allows specifying an external process to launch as part of GPU operations, effectively creating a proxy execution mechanism.

This technique matters because it leverages a trusted, digitally-signed binary (Edge) to launch arbitrary processes, potentially bypassing application allowlisting or process monitoring focused only on direct execution. Detection engineers typically focus on unusual command-line patterns for browsers, process ancestry chains involving browsers launching unexpected child processes, and suspicious parameters like `--gpu-launcher` that facilitate process injection or proxy execution.

## What This Dataset Contains

The dataset captures a complete execution of the Edge GPU launcher technique. The key evidence includes:

**PowerShell Script Block (EID 4104)**: Shows the complete technique implementation including Edge path detection and execution: `& $edgePath --disable-gpu-sandbox --gpu-launcher="C:\\Windows\\System32\\calc.exe &&"`

**Process Creation Chain**: Security EID 4688 events show the process ancestry from PowerShell → PowerShell (child) → Edge → followed by cleanup taskkill processes. The critical Edge process creation shows: `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --disable-gpu-sandbox "--gpu-launcher=C:\\Windows\\System32\\calc.exe &&"`

**Sysmon Process Events**: EID 1 events capture the technique execution with full command lines, showing Edge launched with suspicious parameters designed to execute calc.exe as a proxy.

**Process Access Events**: Sysmon EID 10 events show PowerShell accessing the Edge process (GrantedAccess: 0x1FFFFF), indicating monitoring or control of the spawned process.

**Process Exit Evidence**: Security EID 4689 shows Edge exiting with status 0x3EA (1002), suggesting the technique execution completed but with an error status.

## What This Dataset Does Not Contain

The dataset is missing the actual calc.exe process creation that should have been spawned by Edge's GPU launcher. No Sysmon EID 1 events show calc.exe being created as a child of msedge.exe, and no Security EID 4688 events capture this spawning. This absence suggests Windows Defender or other security controls may have blocked the actual proxy execution, allowing only the Edge process to start but preventing it from successfully launching the target payload.

The dataset also lacks any network connections from Edge (no Sysmon EID 3 events), which is expected since this is purely a local process execution technique. Additionally, there are no file creation events related to the technique itself, as it operates entirely in memory through process spawning.

## Assessment

This dataset provides excellent detection opportunities for the attempt phase of T1218.15 but limited visibility into successful payload execution. The PowerShell script blocks and process creation events clearly demonstrate the technique's implementation with full command-line visibility. However, the apparent blocking of the actual calc.exe spawning limits the dataset's utility for understanding the complete attack flow and post-exploitation behaviors.

The Security audit logs provide complementary coverage to Sysmon, ensuring detection opportunities exist even in environments with limited Sysmon deployment. The combination of PowerShell logging, process creation auditing, and Sysmon process monitoring creates robust detection coverage for this technique variant.

## Detection Opportunities Present in This Data

1. **Edge GPU Launcher Parameter Detection**: Monitor for msedge.exe processes with `--gpu-launcher` command-line parameter, especially when specifying system binaries or unusual executables
2. **Browser Process Ancestry Anomalies**: Alert on Edge processes spawned by PowerShell or other scripting engines, particularly with suspicious command-line arguments
3. **PowerShell Script Block Analysis**: Detect PowerShell scripts that dynamically locate and execute browser binaries with unusual parameters
4. **Process Creation Chain Analysis**: Monitor for PowerShell → PowerShell → msedge.exe process chains, especially when intermediate PowerShell processes have embedded browser execution commands
5. **Edge Parameter Combination Detection**: Alert on Edge processes launched with both `--disable-gpu-sandbox` and `--gpu-launcher` parameters, as this combination is rarely legitimate
6. **Browser Process Access Monitoring**: Detect when PowerShell or other processes open handles to browser processes with full access rights (0x1FFFFF)
7. **Rapid Process Cleanup Patterns**: Monitor for immediate taskkill operations targeting browser processes after short-lived executions, indicating potential LOLBAS cleanup
8. **Test-Path PowerShell Cmdlet Abuse**: Detect PowerShell scripts using Test-Path to locate browser executables in both Program Files directories, suggesting automated LOLBAS discovery
