#!/bin/sh
# Audits the seeded stale inventory and the hardened inventory.
set -u
export PYTHONPATH="$(dirname "$0")/src"

echo "=== Auditing samples/stale-image-inventory.json ==="
python3 -m oci_custom_image_audit samples/stale-image-inventory.json
echo "exit code: $? (2 = high-severity findings present, expected for the seeded sample)"
echo
echo "=== Auditing samples/hardened-image-inventory.json ==="
python3 -m oci_custom_image_audit samples/hardened-image-inventory.json
echo "exit code: $? (0 = no high-severity findings, expected for the hardened sample)"
