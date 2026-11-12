# Additive Manufacturing Merged Threat Taxonomy (AMTT)

A taxonomy of attacks on the additive manufacturing (AM) digital thread, with three annotations on every node: the security property affected (CIA), the requirement of the EU Cyber Resilience Act (CRA) that the threat engages, and, for attack methods, the MITRE ATT&CK mitigations that address it.

It merges two published AM threat taxonomies, Yampolskiy et al. (2018) and Kumar et al. (2025), into 72 nodes: 5 attack goals, 24 attack targets in 5 families and 29 attack methods in 9 families.

The taxonomy supports the companion paper *Navigating the EU Cyber Resilience Act in Additive Manufacturing: Threat Analysis, Standards Mapping, and Compliance Strategies*.

## Start here

| If you want to | Read |
|---|---|
| understand and use the taxonomy | [`3.0-additive-manufacturing-merged-threat-taxonomy.md`](3.0-additive-manufacturing-merged-threat-taxonomy.md), Sections A to D |
| look up a threat | Sections 1 to 3 of the same document |
| see how a threat relates to the CRA | Section 5, and the rule behind the labels in Section C.3 |
| write a threat record for a risk assessment | Section D, with a worked example |
| load the data into a tool | the CSV files under [`taxonomy-data/amtt-3.0/3.0-R1/`](taxonomy-data/amtt-3.0/3.0-R1/) |
| see what changed since the draft | [`CHANGELOG.md`](CHANGELOG.md) |

## Contents of the repository

```text
3.0-additive-manufacturing-merged-threat-taxonomy.md   the taxonomy (human-readable, authoritative)
taxonomy-data/amtt-3.0/3.0-R1/
  releases.csv, nodes.csv, paths.csv                    node and path registers
  authoring-audit/                                      relationships read from the source figures, mappings, path evidence
  annotations/                                          CIA, CRA and ATT&CK annotations as CSV
tools/check_release.py                                  consistency checks for a release
CITATION.cff, CHANGELOG.md, LICENSE, NOTICE
```

## CRA strength labels in one paragraph

The CRA regulates products with digital elements, not files or parts. Each node is therefore labelled by whether its mechanism operates on or through an AM product. **Direct**: it always does, and Annex I addresses it. **Conditional**: it does in some implementations, and the condition is stated. **Partial**: the threat is physical, material, legal or commercial, and Annex I reaches a stated part of it. **Mostly outside CRA**: no AM product is in the path. Of the 58 goals and leaves, 24 are Direct, 21 Conditional, 10 Partial and 3 Mostly outside CRA.

## Status and limits

The taxonomy is derived from the literature and has been demonstrated on one case study. It has not been validated by practitioners. The CRA mapping is the authors' reading of the regulation. It is not legal advice and does not show that any product complies. See Section 10 of the taxonomy document.

## Checking a release

```bash
python3 tools/check_release.py .
```

The script checks node counts, identifiers, the strength vocabulary, the family rule, links to files, agreement between the document and the CSV files, and that no release placeholder is left.

## How to cite

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24158297.svg)](https://doi.org/10.5281/zenodo.24158297)

Please cite the archived release: https://doi.org/10.5281/zenodo.24158297. The citation details are in [`CITATION.cff`](CITATION.cff), and GitHub shows them under *Cite this repository*.

## Licence

The taxonomy document and the data files are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): you may use and adapt them, including commercially, if you give credit. The script in `tools/` is licensed under MIT. See [`LICENSE`](LICENSE).

The MITRE ATT&CK mitigation names, identifiers and descriptions are not covered by this licence. They are © 2026 The MITRE Corporation and are reproduced and distributed with the permission of The MITRE Corporation under the ATT&CK terms of use, which are reproduced in [`NOTICE`](NOTICE). The source taxonomies belong to their authors and publishers and are cited, not reproduced.

## Acknowledgement

This work was supported by the SECUREAM project, Digital Research Centre Denmark, Danish National Defence Technology Centre, and Industriens Fond under Grant No. 25808.

## Contact

Sami Gawad, sagaw22@student.sdu.dk
