# oci-custom-image-audit

Offline auditor for **simplified OCI custom compute image inventories**. Custom images accumulate quietly: old base versions, end-of-life operating systems, oversized bakes, untagged orphans. This tool reads a static JSON inventory and reports the images that need attention.

## What it is

A command-line review tool for image inventory-as-data. Point it at an inventory JSON, get a severity-sorted findings list and an exit code suitable for CI gates.

- Runs 100% locally. No OCI SDK, no credentials, no network calls.
- Six rules (IMG001-IMG006), each unit-tested on positive and negative inputs.
- Exit code 2 when any HIGH finding exists (end-of-life OS); 0 when no HIGH finding exists; 1 on unreadable or malformed input.
- Age is computed against the document's own `reference_time`, so audits are reproducible and safe to run in CI.

## What it is NOT (honest limits)

- The input schema is a **simplified approximation** of custom image metadata. It is not the OCI API response shape, and the tool does not fetch inventories from a tenancy.
- The end-of-life list is conservative and well-known (Oracle Linux 6, CentOS, Ubuntu 14/16/18, Windows Server 2012/2012 R2); it is not a complete EOL database. Absence of IMG002 is not proof an OS is supported.
- Staleness (>180 days), size (>400 GB), and keep-3-versions thresholds are local conventions, tunable by editing `rules.py`. Version grouping strips a `-vN` suffix; other naming schemes are not detected.
- The tool reviews image metadata only. It cannot see what is inside an image (packages, CVEs) or whether it is in use.

## Input schema

```json
{
  "reference_time": "2026-11-08T00:00:00Z",
  "images": [
    {
      "name": "web-base-v3",
      "operating_system": "Oracle Linux",
      "operating_system_version": "8.10",
      "created_at": "2026-10-20T09:30:00Z",
      "size_gb": 47,
      "launch_mode": "PARAVIRTUALIZED",
      "tags": {"owner": "web-team"}
    }
  ]
}
```

## Rules

| Rule | Severity | Finding |
| --- | --- | --- |
| IMG001 | MEDIUM | Image older than 180 days (or unparseable created_at); likely missing months of OS patches |
| IMG002 | HIGH | Operating system past vendor end-of-life; no more security fixes |
| IMG003 | MEDIUM | Image over 400 GB; review what is baked in (cost, slow provisioning) |
| IMG004 | LOW | EMULATED launch mode; use PARAVIRTUALIZED unless required |
| IMG005 | LOW | More than 3 retained versions of one base name |
| IMG006 | MEDIUM | No `owner` tag; image cannot be attributed for review or cleanup |

## Run

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_custom_image_audit samples/stale-image-inventory.json
PYTHONPATH=src python3 -m oci_custom_image_audit samples/hardened-image-inventory.json
```

Or the end-to-end demo (stale inventory -> hardened inventory, with expected exit codes):

```sh
sh demo.sh
```

Expected demo output: the seeded inventory reports 2 high, 7 medium, 2 low findings and exits 2; the hardened inventory reports zero findings and exits 0.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

20 unit tests cover every rule on positive and negative inputs, EOL OS variants, version grouping, sort order, malformed-input handling, and CLI exit codes. CI runs the same tests plus the demo on Python 3.10/3.11/3.12.
