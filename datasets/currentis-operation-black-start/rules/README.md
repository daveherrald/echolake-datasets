# Detection rules

Detection content for this dataset, grouped by rule format so a dataset can ship
more than one kind of rule.

| Directory | Format | Contents |
|-----------|--------|----------|
| [`sigma/`](sigma/) | [Sigma](https://sigmahq.io/) | 13 rules following the kill chain, each verified against this dataset's logs, with backend conversions and a pySigma pipeline. See [`sigma/README.md`](sigma/README.md). |

Additional formats such as YARA or Suricata would be added as sibling directories
(`yara/`, `suricata/`).
