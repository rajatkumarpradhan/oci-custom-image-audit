"""Audit rules for simplified OCI custom image inventory documents.

The input schema is a static, simplified JSON approximation of custom compute
image metadata (OS, creation time, size, launch mode, tags). It is NOT the OCI
API shape; see README.md. Age is computed against the document's own
'reference_time' so audits are reproducible. All analysis is offline.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

STALE_DAYS = 180
LARGE_SIZE_GB = 400
KEEP_VERSIONS = 3

# Operating systems past vendor end-of-life (conservative, well-known entries).
def _is_eol(os_name, os_version):
    name = (os_name or "").lower()
    version = (os_version or "").strip()
    major = version.split(".")[0] if version else ""
    if name.startswith("oracle linux") and major in ("6",):
        return True
    if name.startswith("centos"):
        return True
    if name.startswith("ubuntu") and major in ("14", "16", "18"):
        return True
    if name.startswith("windows server") and version in ("2012", "2012 R2"):
        return True
    return False


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    image: str
    message: str


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def rule_stale_image(image, reference_time):
    """IMG001: image older than STALE_DAYS against the reference time."""
    created = _parse_time(image.get("created_at"))
    name = image.get("name", "<unnamed>")
    if created is None:
        yield Finding("IMG001", "MEDIUM", name, "created_at is missing or unparseable; age cannot be assessed")
        return
    age = (reference_time - created).days
    if age > STALE_DAYS:
        yield Finding("IMG001", "MEDIUM", name,
                      f"image is {age} days old (over {STALE_DAYS}); likely missing months of OS patches")


def rule_eol_os(image, reference_time):
    """IMG002: image runs an operating system past vendor end-of-life."""
    if _is_eol(image.get("operating_system"), image.get("operating_system_version")):
        yield Finding("IMG002", "HIGH", image.get("name", "<unnamed>"),
                      f"{image.get('operating_system')} {image.get('operating_system_version')} is past end-of-life; no more vendor security fixes")


def rule_large_image(image, reference_time):
    """IMG003: unusually large image (storage cost and slow provisioning)."""
    size = image.get("size_gb")
    if isinstance(size, (int, float)) and size > LARGE_SIZE_GB:
        yield Finding("IMG003", "MEDIUM", image.get("name", "<unnamed>"),
                      f"image is {size} GB (over {LARGE_SIZE_GB} GB); review what is baked in")


def rule_emulated_launch(image, reference_time):
    """IMG004: EMULATED launch mode (legacy compatibility, slower boot)."""
    if (image.get("launch_mode") or "").upper() == "EMULATED":
        yield Finding("IMG004", "LOW", image.get("name", "<unnamed>"),
                      "launch mode EMULATED; use PARAVIRTUALIZED unless the OS genuinely requires emulation")


def rule_missing_owner_tag(image, reference_time):
    """IMG006: no owner tag; orphaned images cannot be attributed."""
    tags = image.get("tags") or {}
    if not tags.get("owner"):
        yield Finding("IMG006", "MEDIUM", image.get("name", "<unnamed>"),
                      "no 'owner' tag; the image cannot be attributed for review or cleanup")


def rule_duplicate_versions(document, reference_time):
    """IMG005: more than KEEP_VERSIONS retained versions of the same base name."""
    groups = {}
    for image in document.get("images") or []:
        if not isinstance(image, dict):
            continue
        base = (image.get("name") or "").rsplit("-v", 1)[0]
        groups.setdefault(base, []).append(image.get("name", "<unnamed>"))
    for base, names in groups.items():
        if base and len(names) > KEEP_VERSIONS:
            yield Finding("IMG005", "LOW", base,
                          f"{len(names)} retained versions of '{base}' (keep {KEEP_VERSIONS}); old versions cost storage and confuse launches")


RULES = (rule_stale_image, rule_eol_os, rule_large_image, rule_emulated_launch, rule_missing_owner_tag)


def audit_document(document):
    reference_time = _parse_time(document.get("reference_time")) or datetime.now(timezone.utc)
    findings = []
    for image in document.get("images") or []:
        if not isinstance(image, dict):
            continue
        for rule in RULES:
            findings.extend(rule(image, reference_time))
    findings.extend(rule_duplicate_versions(document, reference_time))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.image, f.message))
