#!/usr/bin/env python3
"""Generate MITRE Attack Flow v2.0.0 STIX 2.1 bundles for the datasets.

Three paths:

1. Curated SCENARIOS (below): narrative multi-stage intrusions, each defined as
   an ordered list of stages (name, ATT&CK technique id, description). One flow
   per scenario dataset.

2. Auto-derived COLLECTION datasets (e.g. Atomic Red Team, Splunk detections): a
   parent dir of many single-purpose subdirs, each with its own dataset.yaml
   mitre_attack block. One flow per subdir, derived straight from that block.
   Chains that are technique coverage rather than a sequence (splunk-detections)
   are emitted unordered (chained=False). The script also inserts an attack_flow
   pointer into each subdir's dataset.yaml.

3. Curated BOTS multi-scenario flows: Boss of the SOC captures carry no
   mitre_attack block, so their independent sub-scenarios are hand-authored
   (BOTS_SCENARIOS) and emitted as separate connected chains within one flow.

Each flow emits a STIX 2.1 bundle with:

  - the canonical Attack Flow extension-definition,
  - an identity (created_by_ref),
  - an attack-flow root SDO (start_refs -> first action),
  - one attack-action per stage, chained via effect_refs,
  - one attack-pattern per distinct technique (external_references -> ATT&CK).

Deterministic: object ids are uuid5 over a per-flow namespace so re-running
produces byte-stable output. Written to datasets/<...>/attack_flow.json.

Grounded strictly in each dataset's own mitre_attack block plus the recorded
kill-chain order; no techniques are invented here.
"""

import json
import uuid
from pathlib import Path

# Canonical Attack Flow extension-definition id (fixed by the CTID spec).
AF_EXT_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
AF_EXT = {AF_EXT_ID: {"extension_type": "new-sdo"}}

# Stable timestamps so output is byte-reproducible.
CREATED = "2026-09-08T00:00:00.000Z"

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"

# ns for deterministic ids, one per scenario keeps ids scoped and stable.
BASE_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


# Each scenario: dataset dir name -> (flow name, flow description, [stages]).
# A stage is (action_name, technique_id, description). Order is the chain order.
SCENARIOS = {
    "thebiggerinterview": (
        "TheBiggerInterview: CI/CD to Kubernetes to AWS compromise",
        "A GitHub Actions workflow vulnerability leads to CI/CD supply-chain "
        "compromise, a Kubernetes tenant foothold, node and cluster compromise, "
        "and durable AWS persistence with database exfiltration. Seven phases "
        "correlated across GitHub audit, EKS audit, CrowdStrike EDR, and AWS "
        "CloudTrail. Chain order per the unsecure.sh scenario writeup.",
        [
            ("P1 CI/CD compromise via GitHub Actions cache poisoning", "T1195.002",
             "Unauthorized PR triggers a workflow on the dev ref that writes a backdoored artifact into the Actions cache."),
            ("P2 Supply-chain poisoning of the container image", "T1525",
             "The trusted release job restores the poisoned cache entry and bakes the backdoored entrypoint into the production image."),
            ("P2 Backdoored host software binary shipped", "T1554",
             "The compromised application binary is distributed in the pushed image."),
            ("P3 Tenant foothold via backdoored app", "T1610",
             "app-1 pulls the backdoored image; an in-memory beacon executes in an unprivileged namespace."),
            ("P3 Container and resource discovery", "T1613",
             "The beacon reads env and files to discover the monitoring service and cluster resources."),
            ("P3 Steal monitoring service-account token", "T1528",
             "Arbitrary file read yields the monitoring-sa projected token (get pods cluster-wide, nodes/proxy)."),
            ("P4 Exec into node debug pod (escape to host)", "T1611",
             "The beacon reaches the kubelet and execs into an operator's node debug pod, whose host mount gives root via chroot."),
            ("P4 Kernel rootkit installed as static pod", "T1547.006",
             "An LKM plus eBPF rootkit is written as a static pod manifest and loaded by restarting the kubelet, with no API-server record."),
            ("P4 Rootkit conceals node activity", "T1014",
             "The kernel rootkit hides the implant's processes and network activity on the node."),
            ("P5 Harvest CI runner credentials from files", "T1552.001",
             "The rootkit harvests AWS credentials present on the node filesystem."),
            ("P5 Cross-tenant escalation to cluster-admin", "T1078.004",
             "A backdoored orchestrator image is pulled by the privileged tenant; the cluster-admin orchestrator-sa token is stolen, and the ack-lambda-controller IRSA token with it."),
            ("P6 Account manipulation, cross-account IAM into aws-auth", "T1098",
             "orchestrator-sa patches aws-auth to add a cross-account IAM user for durable cluster access."),
            ("P6 Serverless persistence via ephemeral Lambdas", "T1648",
             "Lambdas (save-logging, iac-*) are created via PassRole onto a privileged role, plus a durable save-logging-info implant and an hourly EventBridge rule; iac-* peer VPCs and open RDS/EKS security groups."),
            ("P7 Collect application databases", "T1530",
             "The peered link is used to reach and dump the application databases."),
            ("P7 Exfiltration over web service", "T1567",
             "save-logging-info exfiltrates harvested AWS admin credentials on every hourly run; database contents are exfiltrated over the peered path."),
        ],
    ),
    "currentis-operation-black-start": (
        "Operation Black Start: agentic prompt-injection to IT-to-OT pre-positioning",
        "A fictional ICS/OT intrusion at Currentis Energy. Prompt injection of an "
        "agentic assistant leads to LOTL recon, an HTTP C2 beacon, LSASS credential "
        "theft, an IT-to-OT pivot on a stolen vendor account, OT reconnaissance, "
        "low-and-slow exfiltration, and a log clear, ending in staged (not fired) "
        "OT manipulation. Chain order per the Black Start kill-chain.",
        [
            ("Prompt-injection initial access", "T1566",
             "A poisoned NERC CIP document from a trusted sender is auto-processed by the rchen OpenClaw assistant."),
            ("User execution of the stager", "T1204",
             "The assistant executes an embedded instruction as the rchen user."),
            ("PowerShell stager", "T1059.001",
             "A base64 PowerShell stager runs; the on-host attack descends from the agent."),
            ("Deobfuscate staged payload", "T1140",
             "The obfuscated stager content is decoded on host."),
            ("Domain account discovery", "T1087.002",
             "net user/group /domain and AD queries enumerate the domain."),
            ("Masqueraded C2 beacon with Run-key persistence", "T1071.001",
             "kb5041234-v3.exe beacons to the C2 (~60s) with a registry Run-key; the C2 IP is a documented Cobalt Strike indicator."),
            ("LSASS credential dumping", "T1003.001",
             "An LSASS read harvests the cached turbine-vendor credential and a dormant service account."),
            ("IT-to-OT pivot on stolen vendor account (RDP)", "T1021.001",
             "RDP from WS-RACHEL to the SCADA jump host using the stolen helixgrid-svc account. Enterprise T1021.001 / ICS T0859."),
            ("OT reconnaissance / control-loop mapping", "T1083",
             "Enumerate engineering software and pull Unit 3 turbine config and alarm/setpoint data. ICS T0888."),
            ("Collect operational information", "T1005",
             "Turbine config and alarm data are staged from the local system. ICS T0882."),
            ("Low-and-slow exfiltration over C2", "T1041",
             "Turbine config and alarm data trickle out the C2 channel, staged small."),
            ("Stage OT manipulation, then clear logs", "T1070.001",
             "A Unit 3 setpoint-modification capability is staged but not fired; the Security log is cleared and staging artifacts deleted. ICS T0831 (staged)."),
        ],
    ),
    "paws-operation-yarn-ball": (
        "Operation Yarn Ball: Sliver C2 attack chain",
        "A multi-stage intrusion on the PAWS lab: discovery, DNS-tunneled C2, "
        "LOLBin proxy execution, scheduled-task and Run-key persistence, credential "
        "access, lateral movement over WinRM/SMB, ransomware impact, and a log clear.",
        [
            ("System and network discovery", "T1082",
             "Host, network, and user discovery on the initial workstation."),
            ("DNS-tunneled C2", "T1071.004",
             "A Sliver beacon communicates over DNS."),
            ("LOLBin proxy execution", "T1218",
             "A signed system binary proxies attacker code (defense evasion)."),
            ("Scheduled task and Run-key persistence", "T1053",
             "A scheduled task and a registry Run-key establish persistence."),
            ("Harvest unsecured credentials", "T1552",
             "Credentials are recovered from files and configuration."),
            ("Lateral movement over WinRM/SMB", "T1021.006",
             "The actor moves to additional hosts via Windows Remote Management and admin shares (T1021.002)."),
            ("Remote service execution", "T1569.002",
             "A service is created and started on a remote host to execute payload."),
            ("Exfiltration over C2", "T1041",
             "Collected data is exfiltrated over the Sliver channel."),
            ("Ransomware impact and log clear", "T1486",
             "Data is encrypted for impact; the Security event log is cleared (T1070.001)."),
        ],
    ),
    "ctid-process_injection": (
        "CTID micro-emulation: Process Injection (PE injection)",
        "A CTID micro-emulation of process injection via portable-executable "
        "injection.",
        [
            ("Portable executable injection", "T1055.002",
             "Attacker code is injected into a target process via PE injection (T1055 Process Injection)."),
        ],
    ),
    "ctid-named_pipes": (
        "CTID micro-emulation: Named Pipes (inter-process communication)",
        "A CTID micro-emulation exercising inter-process communication over named "
        "pipes.",
        [
            ("Inter-process communication over named pipes", "T1559",
             "Named-pipe IPC is used for local coordination/execution."),
        ],
    ),
    "ctid-reflective_loading": (
        "CTID micro-emulation: Reflective Code Loading",
        "A CTID micro-emulation of reflective code loading followed by light "
        "discovery.",
        [
            ("Reflective code loading", "T1620",
             "Code is loaded reflectively into memory, avoiding the on-disk image (defense evasion)."),
            ("System information discovery", "T1082",
             "Host information is enumerated after load."),
            ("System network connections discovery", "T1049",
             "Active network connections are enumerated."),
        ],
    ),
    "ctid-log_clearing": (
        "CTID micro-emulation: Clear Windows Event Logs",
        "A CTID micro-emulation of Windows event-log clearing.",
        [
            ("Clear Windows event logs", "T1070.001",
             "Windows event logs are cleared to remove indicators (defense evasion)."),
        ],
    ),
    "ctid-log_clearing_full": (
        "CTID micro-emulation: Clear Windows Event Logs (full)",
        "A CTID micro-emulation of Windows event-log clearing (full-capture "
        "variant).",
        [
            ("Clear Windows event logs", "T1070.001",
             "Windows event logs are cleared to remove indicators (defense evasion)."),
        ],
    ),
}


# Auto-derived collection datasets: parent dir -> config. Each subdir with a
# dataset.yaml mitre_attack block becomes one flow, derived from that block.
#   flow_label: fn(subdir_name, technique_name) -> STIX flow name
#   pointer_desc: fn(subdir_name, technique_name) -> short dataset.yaml pointer
#     description (must be a colon-free plain YAML scalar)
COLLECTIONS = {
    "art": {
        "flow_label": lambda sub, tname: f"Atomic Red Team {sub[len('art-'):] if sub.startswith('art-') else sub}: {tname}",
        "pointer_desc": lambda sub, tname: f"{tname} (Atomic Red Team {sub[len('art-'):] if sub.startswith('art-') else sub})",
    },
    # Splunk detections enumerate the techniques a rule covers, not an executed
    # sequence. Emit an UNORDERED coverage flow: one attack-action per covered
    # technique, no effect_refs, every action a start_ref. Names fall back to the
    # technique id because the source blocks carry placeholder technique names.
    "splunk-detections": {
        "flow_label": lambda sub, tname: f"Detection technique coverage: {sub}",
        "pointer_desc": lambda sub, tname: f"MITRE ATT&CK technique coverage for detection {sub}",
        "chained": False,
    },
}


# ---- Boss of the SOC (BOTS) curated multi-scenario flows -------------------
# BOTS dataset.yaml files carry no mitre_attack block, so these chains are
# hand-authored from the published scenario analysis. Each version's independent
# sub-scenarios are emitted as separate connected chains within one flow (one
# start_ref per sub-scenario). Grounded in the public scenario and its analyst-
# derived ATT&CK mapping; Splunk publishes no official ATT&CK layer for BOTS.
BOTS_NOTE = (
    "Fictional Splunk Boss of the SOC CTF scenario. The ATT&CK mapping is derived "
    "from the published scenario analysis; no official Splunk ATT&CK layer exists "
    "for BOTS."
)

# canonical key -> (flow name, flow description, [sub-scenario chains]).
# Each sub-scenario chain is an ordered list of (action_name, technique_id, desc).
BOTS_SCENARIOS = {
    "v1": (
        "Boss of the SOC v1: Po1s0n1vy against Wayne Enterprises",
        "Two 2016 campaigns against Wayne Enterprises (imreallynotbatman.com): a "
        "Joomla web-application compromise ending in external defacement, and a "
        "Cerber ransomware infection delivered by a planted USB. " + BOTS_NOTE,
        [
            [
                ("Acquire actor and lookalike domains", "T1583.001",
                 "The actor registers actor-owned and lookalike domains used across the campaign."),
                ("Web vulnerability scanning of the Joomla site", "T1595",
                 "Automated web vulnerability scanning enumerates the public Joomla CMS and its admin panel."),
                ("Brute-force the Joomla administrator login", "T1110.001",
                 "Password guessing against the Joomla admin account succeeds after hundreds of attempts."),
                ("Abuse the public-facing Joomla admin panel", "T1190",
                 "The actor authenticates to the public-facing Joomla admin with the guessed credential."),
                ("Upload a malicious executable web component", "T1505.003",
                 "A malicious executable is uploaded through the admin panel and served from the web server."),
                ("HTTP command and control", "T1071.001",
                 "The compromised server beacons to attacker infrastructure over HTTP."),
                ("External website defacement", "T1491.002",
                 "Site content is replaced with a defacement image pulled from attacker dynamic-DNS infrastructure."),
            ],
            [
                ("Planted USB carrying a malicious document", "T1091",
                 "A USB drive with a macro-enabled document is planted and inserted by an employee."),
                ("User opens the malicious file", "T1204.002",
                 "The employee opens the document, starting execution."),
                ("VBScript launcher execution", "T1059.005",
                 "A VBScript launcher runs via wscript.exe to stage the ransomware."),
                ("Reach the file server over SMB", "T1021.002",
                 "The ransomware reaches a file server over SMB and admin shares to widen impact."),
                ("Cerber file encryption for impact", "T1486",
                 "Cerber encrypts local and file-server documents, appending its extension."),
            ],
        ],
    ),
    "v2": (
        "Boss of the SOC v2: Taedonggang APT and more against Frothly",
        "Four 2017 scenarios against Frothly: a Taedonggang APT intrusion via "
        "spearphishing and PowerShell Empire, macOS Patcher ransomware from a "
        "planted USB, an insider-threat espionage case, and web-application SQL "
        "injection and XSS. " + BOTS_NOTE,
        [
            [
                ("Spearphishing attachment", "T1566.001",
                 "A password-protected ZIP attachment is delivered by spearphishing email."),
                ("User opens the malicious attachment", "T1204.002",
                 "The recipient opens the attachment, executing the embedded payload."),
                ("PowerShell Empire execution", "T1059.001",
                 "A PowerShell Empire agent runs on the host."),
                ("AMSI bypass to impair defenses", "T1562.001",
                 "The agent bypasses AMSI to evade PowerShell security controls."),
                ("Decode staged PowerShell", "T1140",
                 "Base64-encoded PowerShell content is decoded on host."),
                ("Registry Run-key persistence", "T1547.001",
                 "Encoded PowerShell is stored under a registry Run key for persistence."),
                ("Scheduled-task persistence", "T1053.005",
                 "A daily scheduled task re-launches the C2 beacon."),
                ("Web-protocol C2 callback", "T1071.001",
                 "The agent beacons to a C2 endpoint over web protocols."),
                ("Encrypted C2 channel", "T1573.002",
                 "C2 traffic is protected by a self-signed SSL certificate."),
                ("Dynamic-DNS C2 resolution", "T1568.002",
                 "C2 domains resolve through dynamic-DNS providers for resilience."),
                ("Exfiltration over the C2 channel", "T1041",
                 "Collected data is exfiltrated over the C2 channel."),
                ("Exfiltration over FTP and BitTorrent", "T1048.003",
                 "Additional data moves over unencrypted FTP and BitTorrent."),
            ],
            [
                ("Planted USB delivery", "T1091",
                 "A USB drive carrying a malware archive is planted for a target user."),
                ("User runs the disguised malware", "T1204.002",
                 "The user opens the archive and runs the disguised ransomware."),
                ("Timestomp for anti-forensics", "T1070.006",
                 "File timestamps are set to a false past date to frustrate analysis."),
                ("macOS file encryption for impact", "T1486",
                 "The Patcher ransomware encrypts files, appending its extension."),
            ],
            [
                ("Research a competitor's public site", "T1593",
                 "The insider researches a competitor brewery through open web sources."),
                ("Collect proprietary data from the workstation", "T1005",
                 "Proprietary research documents are gathered from the local system."),
                ("Exfiltrate over personal web-mail", "T1567",
                 "Trade-secret files are sent out through a personal web-mail account."),
            ],
            [
                ("Vulnerability scanning of the forum", "T1595.002",
                 "The public forum application is scanned for vulnerabilities."),
                ("SQL injection against the forum", "T1190",
                 "SQL injection extracts forum user credentials and password hashes."),
                ("Abuse a fraudulently created admin account", "T1078.001",
                 "A stolen session and CSRF token yield a fraudulently created admin account."),
            ],
        ],
    ),
    "v3": (
        "Boss of the SOC v3: cloud compromise against Frothly",
        "Four 2018 scenarios against Frothly's cloud estate: an S3 "
        "misconfiguration leading to browser cryptojacking, abuse of leaked AWS "
        "credentials, a memcached-amplification DDoS, and a Microsoft 365 data "
        "exfiltration. " + BOTS_NOTE,
        [
            [
                ("Misconfigured public S3 bucket", "T1190",
                 "A public-facing S3 bucket is left world-accessible via a permissive ACL."),
                ("Place and serve content from cloud storage", "T1530",
                 "Attacker-supplied content is placed in and served from the cloud storage bucket."),
                ("Malicious link drives the browser to a miner", "T1204.001",
                 "An employee's browser is redirected to browser-based mining infrastructure."),
                ("Coinhive delivered via web service", "T1102",
                 "The mining JavaScript is delivered through a third-party web service."),
                ("Browser cryptomining resource hijacking", "T1496",
                 "Monero mining runs in employee browsers, saturating CPU."),
            ],
            [
                ("Reuse leaked cloud credentials", "T1078.004",
                 "A valid AWS access key leaked in a public repository is reused."),
                ("Cloud infrastructure discovery", "T1580",
                 "The actor enumerates cloud resources and IAM through API calls."),
                ("Add cloud credentials for persistence", "T1098.001",
                 "The actor attempts to create IAM users and additional access keys."),
                ("Mass EC2 launch for resource hijacking", "T1496",
                 "Hundreds of RunInstances calls attempt to spin up EC2 compute for mining."),
            ],
            [
                ("Memcached reflection-amplification DDoS", "T1498.002",
                 "A memcached UDP amplification flood targets the forum, preceded by DNS subdomain enumeration."),
            ],
            [
                ("Remote email and file collection in M365", "T1114.002",
                 "OneDrive, SharePoint, and mailbox contents are accessed in Microsoft 365."),
                ("Exfiltrate over web service by email BCC", "T1567",
                 "Data is exfiltrated by BCC to an external web-mail address."),
            ],
        ],
    ),
}

# bots subdir -> (canonical scenario key, variant label).
BOTS_VARIANTS = {
    "botsv1": ("v1", "full capture"),
    "botsv1-2026": ("v1", "2026 time-shifted"),
    "botsv2": ("v2", "full capture"),
    "botsv2-2026": ("v2", "2026 time-shifted"),
    "botsv2-attack-only": ("v2", "attack-only subset"),
    "botsv2-attack-only-2026": ("v2", "attack-only subset, 2026 time-shifted"),
    "botsv3": ("v3", "full capture"),
    "botsv3-2026": ("v3", "2026 time-shifted"),
}


def det_id(ns: uuid.UUID, stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(ns, stix_type + ':' + key)}"


def build_bundle(dir_name: str, flow_name: str, flow_desc: str, stages, chained: bool = True):
    ns = uuid.uuid5(BASE_NS, dir_name)
    identity_id = det_id(ns, "identity", "echolake")
    flow_id = det_id(ns, "attack-flow", dir_name)

    objects = []

    # extension-definition (canonical Attack Flow)
    objects.append({
        "type": "extension-definition",
        "spec_version": "2.1",
        "id": AF_EXT_ID,
        "created_by_ref": identity_id,
        "created": "2022-08-02T19:34:35.143Z",
        "modified": "2022-08-02T19:34:35.143Z",
        "name": "Attack Flow",
        "description": "Extends STIX 2.1 with features to create Attack Flows.",
        "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
        "version": "2.0.0",
        "extension_types": ["new-sdo"],
    })

    # identity (author)
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": CREATED,
        "modified": CREATED,
        "name": "EchoLake Project",
        "identity_class": "organization",
    })

    # attack-pattern per distinct technique
    tech_ids = []
    tech_name = {}
    for name, tid, _ in stages:
        if tid not in tech_ids:
            tech_ids.append(tid)
            tech_name.setdefault(tid, name)
    ap_ref = {}
    for tid in tech_ids:
        apid = det_id(ns, "attack-pattern", tid)
        ap_ref[tid] = apid
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": apid,
            "created": CREATED,
            "modified": CREATED,
            "name": tid,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid}
            ],
        })

    # attack-action per stage, chained
    action_ids = [det_id(ns, "attack-action", f"{i}:{name}") for i, (name, _, _) in enumerate(stages)]
    for i, (name, tid, desc) in enumerate(stages):
        action = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": action_ids[i],
            "created": CREATED,
            "modified": CREATED,
            "name": name,
            "technique_id": tid,
            "technique_ref": ap_ref[tid],
            "description": desc,
            "extensions": AF_EXT,
        }
        if chained and i + 1 < len(stages):
            action["effect_refs"] = [action_ids[i + 1]]
        objects.append(action)

    # attack-flow root SDO
    flow = {
        "type": "attack-flow",
        "spec_version": "2.1",
        "id": flow_id,
        "created_by_ref": identity_id,
        "created": CREATED,
        "modified": CREATED,
        "name": flow_name,
        "description": flow_desc,
        "scope": "incident",
        "start_refs": [action_ids[0]] if chained else list(action_ids),
        "extensions": AF_EXT,
    }
    # attack-flow object goes at the front of the objects list per convention.
    objects.insert(2, flow)

    bundle_id = det_id(ns, "bundle", dir_name)
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def build_multichain_bundle(dir_key: str, flow_name: str, flow_desc: str, subchains):
    """Like build_bundle, but takes several independent sub-scenario chains. Each
    chain is linked internally via effect_refs; the flow lists one start_ref per
    chain. Kept separate from build_bundle so single-chain output stays byte-stable."""
    ns = uuid.uuid5(BASE_NS, dir_key)
    identity_id = det_id(ns, "identity", "echolake")
    flow_id = det_id(ns, "attack-flow", dir_key)

    objects = []
    objects.append({
        "type": "extension-definition",
        "spec_version": "2.1",
        "id": AF_EXT_ID,
        "created_by_ref": identity_id,
        "created": "2022-08-02T19:34:35.143Z",
        "modified": "2022-08-02T19:34:35.143Z",
        "name": "Attack Flow",
        "description": "Extends STIX 2.1 with features to create Attack Flows.",
        "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
        "version": "2.0.0",
        "extension_types": ["new-sdo"],
    })
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": CREATED,
        "modified": CREATED,
        "name": "EchoLake Project",
        "identity_class": "organization",
    })

    # attack-pattern per distinct technique across all chains
    tech_ids = []
    for chain in subchains:
        for _, tid, _ in chain:
            if tid not in tech_ids:
                tech_ids.append(tid)
    ap_ref = {}
    for tid in tech_ids:
        apid = det_id(ns, "attack-pattern", tid)
        ap_ref[tid] = apid
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": apid,
            "created": CREATED,
            "modified": CREATED,
            "name": tid,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid}
            ],
        })

    # actions per chain, chained within each chain
    start_refs = []
    for ci, chain in enumerate(subchains):
        ids = [det_id(ns, "attack-action", f"{ci}:{si}:{name}") for si, (name, _, _) in enumerate(chain)]
        start_refs.append(ids[0])
        for si, (name, tid, desc) in enumerate(chain):
            action = {
                "type": "attack-action",
                "spec_version": "2.1",
                "id": ids[si],
                "created": CREATED,
                "modified": CREATED,
                "name": name,
                "technique_id": tid,
                "technique_ref": ap_ref[tid],
                "description": desc,
                "extensions": AF_EXT,
            }
            if si + 1 < len(chain):
                action["effect_refs"] = [ids[si + 1]]
            objects.append(action)

    flow = {
        "type": "attack-flow",
        "spec_version": "2.1",
        "id": flow_id,
        "created_by_ref": identity_id,
        "created": CREATED,
        "modified": CREATED,
        "name": flow_name,
        "description": flow_desc,
        "scope": "incident",
        "start_refs": start_refs,
        "extensions": AF_EXT,
    }
    objects.insert(2, flow)

    bundle_id = det_id(ns, "bundle", dir_key)
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def _write_bundle(out_path: Path, bundle) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")


def _placeholder_name(name, tid: str) -> str:
    """Splunk-content blocks carry placeholder names like 'Technique T1078.004';
    fall back to the bare id so we never emit a fake technique name."""
    if not name:
        return tid
    n = name.strip()
    if n.lower() == f"technique {tid}".lower():
        return tid
    return n


def stages_from_meta(meta: dict):
    """Build ordered stages from a dataset.yaml metadata block's mitre_attack
    techniques. One stage per listed technique, in listed order."""
    ma = (meta or {}).get("mitre_attack", {}) or {}
    techs = ma.get("techniques") or []
    desc = (meta.get("description") or "").strip()
    stages = []
    for t in techs:
        tid = t.get("id")
        if not tid:
            continue
        name = _placeholder_name(t.get("name"), tid)
        stages.append((name, tid, desc))
    return stages


def ensure_pointer(yaml_path: Path, short_desc: str) -> bool:
    """Insert an attack_flow pointer block just after the top-level 'metadata:'
    line, unless one is already present. Text insertion only, so YAML anchors and
    field ordering in the file are left untouched. Returns True if it wrote."""
    text = yaml_path.read_text(encoding="utf-8")
    if "\n  attack_flow:\n" in text or text.startswith("metadata:\n  attack_flow:\n"):
        return False
    block = (
        "  attack_flow:\n"
        "    path: attack_flow.json\n"
        "    format: stix-2.1\n"
        '    schema_version: "2.0.0"\n'
        f"    description: {short_desc}\n"
    )
    lines = text.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if ln.rstrip("\n") == "metadata:":
            lines.insert(i + 1, block)
            yaml_path.write_text("".join(lines), encoding="utf-8")
            return True
    return False  # no top-level metadata: block; leave the file alone


def gen_scenarios() -> None:
    for dir_name, (name, desc, stages) in SCENARIOS.items():
        out_dir = DATASETS_DIR / dir_name
        if not out_dir.is_dir():
            print(f"SKIP (dir missing): {dir_name}")
            continue
        bundle = build_bundle(dir_name, name, desc, stages)
        out_path = out_dir / "attack_flow.json"
        _write_bundle(out_path, bundle)
        print(f"wrote {out_path}  ({len(stages)} actions, {len(bundle['objects'])} objects)")


def gen_collection(parent: str, cfg: dict) -> None:
    import yaml  # only collections need a YAML reader

    base = DATASETS_DIR / parent
    if not base.is_dir():
        print(f"SKIP (collection dir missing): {parent}")
        return
    made = skipped = pointed = 0
    for sub in sorted(p for p in base.iterdir() if p.is_dir()):
        y = sub / "dataset.yaml"
        if not y.is_file():
            continue
        meta = (yaml.safe_load(y.read_text(encoding="utf-8")) or {}).get("metadata", {}) or {}
        stages = stages_from_meta(meta)
        if not stages:
            skipped += 1
            continue
        tname = stages[0][0]
        rel = f"{parent}/{sub.name}"
        flow_name = cfg["flow_label"](sub.name, tname)
        flow_desc = (meta.get("description") or flow_name).strip()
        bundle = build_bundle(rel, flow_name, flow_desc, stages, chained=cfg.get("chained", True))
        _write_bundle(sub / "attack_flow.json", bundle)
        made += 1
        if ensure_pointer(y, cfg["pointer_desc"](sub.name, tname)):
            pointed += 1
    print(f"collection '{parent}': wrote {made} flows, {pointed} dataset.yaml pointers, {skipped} skipped (no techniques)")


def gen_bots() -> None:
    base = DATASETS_DIR / "bots"
    if not base.is_dir():
        print("SKIP (bots dir missing)")
        return
    made = pointed = 0
    for sub, (key, variant) in BOTS_VARIANTS.items():
        out_dir = base / sub
        if not out_dir.is_dir():
            print(f"SKIP (bots dir missing): {sub}")
            continue
        name, desc, subchains = BOTS_SCENARIOS[key]
        flow_name = f"{name} ({variant})"
        rel = f"bots/{sub}"
        bundle = build_multichain_bundle(rel, flow_name, desc, subchains)
        _write_bundle(out_dir / "attack_flow.json", bundle)
        made += 1
        n_actions = sum(len(c) for c in subchains)
        print(f"wrote {out_dir / 'attack_flow.json'}  ({len(subchains)} chains, {n_actions} actions)")
        y = out_dir / "dataset.yaml"
        if y.is_file() and ensure_pointer(y, f"MITRE ATT&CK attack flow for Boss of the SOC {key} {variant}"):
            pointed += 1
    print(f"bots: wrote {made} flows, {pointed} dataset.yaml pointers")


def main():
    gen_scenarios()
    for parent, cfg in COLLECTIONS.items():
        gen_collection(parent, cfg)
    gen_bots()


if __name__ == "__main__":
    main()
