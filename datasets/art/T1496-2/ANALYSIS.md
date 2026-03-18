# T1496-2: Resource Hijacking — Simulate CPU Load with PowerShell

## Technique Context

T1496 (Resource Hijacking) covers adversary use of a victim's computational resources for their own benefit — most commonly cryptocurrency mining (cryptojacking), but also sustained denial-of-service generation or proxy infrastructure. In the cryptomining variant, attackers deploy miners that consume all available CPU or GPU cycles, degrading endpoint performance and incurring electricity costs for the victim. Detection of resource hijacking historically relied on performance anomalies (CPU utilization alerts), but endpoint telemetry provides more reliable indicators: the processes responsible for the load, their parent chains, and unusual PowerShell execution patterns that create worker jobs to maximize parallelism.

Test 2 simulates the CPU load pattern specifically — it does not deploy an actual miner binary — by spawning four PowerShell background jobs that each run a tight CPU-burning loop for 30 seconds. This produces the PowerShell execution artifacts characteristic of script-based resource hijacking without any external payload.

## What This Dataset Contains

The technique is executed via an inline PowerShell script captured in Security Event ID 4688 and Sysmon Event ID 1:

```
powershell.exe & {
  $end = (Get-Date).AddSeconds(30)
  1..4 | ForEach-Object {
    Start-Job { param($t) while((Get-Date) -lt $t) { $i=0; while($i -lt 200000){$i++} } } -ArgumentList $end
  }
  Get-Job | Wait-Job | Remove-Job
}
```

Sysmon captures five PowerShell process creation events: the initial orchestrator `powershell.exe` (with the full script as the command line) and four child `powershell.exe` processes each launched as `-Version 5.1 -s -NoLogo -NoProfile` — the standard signature of background jobs created by `Start-Job`. The four background job workers all share the same parent PID (the orchestrator PowerShell), making the burst pattern visible in process tree analysis.

The PowerShell/Operational channel is notably richer than most other datasets in this collection. It contains 1,112 events across event IDs 4103, 4104, 8193–8197, and 12039. This volume reflects the sustained 30-second execution with module logging capturing the repeated `Get-Date` invocations inside the CPU loop, producing high-frequency 4103 (module pipeline execution) records. Event ID 4104 captures the script blocks for `Start-Job` lambda bodies and the orchestrating script. The high event volume is itself an artifact of the technique — a burst of PowerShell module logging events from multiple concurrent PowerShell processes over a short window is detectable as anomalous.

## What This Dataset Does Not Contain

- **No miner binary**: This is a pure PowerShell simulation. There are no network connections to mining pools, no GPU activity, and no miner executable creation. A real cryptomining deployment would include process creation for the miner binary and network connections to pool addresses.
- **No Sysmon ProcessCreate for the four background job workers**: The child `powershell.exe -s` processes match the Sysmon include rule for PowerShell (captured via the T1059.001 rule), but only the parent and the four workers are in the Sysmon data. Intermediate Sysmon context is limited to image loads.
- **No CPU performance counter data**: The actual resource consumption is not reflected in event log telemetry; performance monitoring (perfmon, WMI performance classes) would be needed to quantify the impact.

## Assessment

This dataset provides a useful baseline for PowerShell-based resource hijacking detection. The parent-child relationship of five PowerShell processes (one orchestrator, four workers) where all four workers are backgrounded jobs with `-s -NoLogo -NoProfile` flags is a strong structural indicator. The high volume of PowerShell module logging events (1,112) over a 35-second window is itself anomalous and detectable via event rate thresholds. The full script block showing `Start-Job` with CPU-burning loops is captured in the PowerShell 4104 channel. The dataset's value is somewhat limited by the absence of network artifacts that would be present in actual mining activity — it covers the execution pattern but not the full kill chain.

## Detection Opportunities Present in This Data

1. **`powershell.exe` spawning four or more child `powershell.exe -s -NoLogo -NoProfile` processes in rapid succession** — Sysmon Event ID 1 shows the burst of background job workers with identical flags; spawning multiple background PowerShell workers from a single parent in seconds is uncommon outside resource-intensive scripting or abuse.
2. **Security 4688 command line containing `Start-Job` with a CPU loop body (`while`, `ForEach-Object`)** — The full script is captured in the Security channel and includes the tight inner loop structure indicative of intentional CPU saturation.
3. **Spike in PowerShell Event ID 4103 (module logging) rate from multiple concurrent PowerShell processes** — Over 1,000 PowerShell events in 35 seconds from a single host is anomalous; rate-based detection on the PowerShell/Operational channel can identify sustained scripted activity.
4. **`powershell.exe -Version 5.1 -s -NoLogo -NoProfile` with parent `powershell.exe`** — The background job worker signature (`-s` server mode, `-NoLogo -NoProfile`) spawned by an interactive PowerShell session is the standard `Start-Job` artifact; multiple instances simultaneously is a high-confidence indicator.
5. **PowerShell Event IDs 8193/8194/8195/8196/8197** — These Windows Remote Management and workflow-related event IDs appear in the PowerShell channel during background job execution and can be used to identify concurrent job worker activity even without inspecting script content.
