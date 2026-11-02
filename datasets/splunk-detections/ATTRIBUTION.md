# Attribution and modifications

The detection metadata in this directory is derived from [Splunk Security Content](https://github.com/splunk/security_content) at revision `29ece397e8ab7f95fd9055e586dd541859075a9f`. The sample data is referenced from [Splunk attack_data](https://github.com/splunk/attack_data) at revision `f5cea3c0980ca3f3c4c5dafc72330278b35ddbd3`. Copyright 2022 Splunk Inc.

Both upstream Splunk projects are licensed under the Apache License 2.0. A copy is included in [LICENSE](LICENSE). Neither pinned upstream tree contains a `NOTICE` file.

EchoLake modified the upstream material by selecting the 1,866 rules represented by this collection, converting rule metadata to EchoLake manifests, pinning rule and sample-data links, adding SHA-256 integrity values, adding MITRE ATT&CK names and tactics, recording reviewed unmapped rules, and generating the documentation. Each generated manifest records the source rule path, source revision, source rule hash, and a modification notice.

MITRE ATT&CK names and tactics come from Enterprise ATT&CK v18.1 at revision `7ad8a86f41edc91dd37de0487b0c2f44ae3a3af7`. Copyright 2020-2025 The MITRE Corporation. Approved for public release. Case number 19-3504. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.

The required MITRE copyright designation and license are reproduced in [MITRE-ATTACK-LICENSE.txt](MITRE-ATTACK-LICENSE.txt). The upstream license is `LICENSE.txt` at Git blob `11858db5aa4a324ed2a508f35523fbb95e869e0a`. See the [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/).

The immutable inputs are listed in [upstream.lock.yaml](upstream.lock.yaml).
