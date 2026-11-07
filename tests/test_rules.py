import unittest

from oci_custom_image_audit.rules import audit_document

REF = "2026-11-08T00:00:00Z"


def doc(images):
    return {"reference_time": REF, "images": images}


def base_image(**overrides):
    image = {
        "name": "app-v1",
        "operating_system": "Oracle Linux",
        "operating_system_version": "8.10",
        "created_at": "2026-10-01T00:00:00Z",
        "size_gb": 50,
        "launch_mode": "PARAVIRTUALIZED",
        "tags": {"owner": "team-a"},
    }
    image.update(overrides)
    return image


def rule_ids(findings):
    return {f.rule_id for f in findings}


class TestImageRules(unittest.TestCase):
    def test_clean_image_has_no_findings(self):
        self.assertEqual(audit_document(doc([base_image()])), [])

    def test_img001_stale_image(self):
        findings = audit_document(doc([base_image(created_at="2025-01-01T00:00:00Z")]))
        self.assertIn("IMG001", rule_ids(findings))

    def test_img001_missing_created_at(self):
        image = base_image()
        del image["created_at"]
        self.assertIn("IMG001", rule_ids(audit_document(doc([image]))))

    def test_img001_recent_image_ok(self):
        findings = audit_document(doc([base_image(created_at="2026-11-01T00:00:00Z")]))
        self.assertNotIn("IMG001", rule_ids(findings))

    def test_img002_eol_os_oracle_linux_6(self):
        findings = audit_document(doc([base_image(operating_system_version="6.10")]))
        self.assertIn("IMG002", rule_ids(findings))

    def test_img002_eol_os_centos(self):
        findings = audit_document(doc([base_image(operating_system="CentOS", operating_system_version="7.9")]))
        self.assertIn("IMG002", rule_ids(findings))

    def test_img002_eol_os_ubuntu_1804(self):
        findings = audit_document(doc([base_image(operating_system="Ubuntu", operating_system_version="18.04")]))
        self.assertIn("IMG002", rule_ids(findings))

    def test_img002_supported_os_ok(self):
        findings = audit_document(doc([base_image(operating_system="Ubuntu", operating_system_version="22.04")]))
        self.assertNotIn("IMG002", rule_ids(findings))

    def test_img003_large_image(self):
        self.assertIn("IMG003", rule_ids(audit_document(doc([base_image(size_gb=512)]))))

    def test_img003_normal_size_ok(self):
        self.assertNotIn("IMG003", rule_ids(audit_document(doc([base_image(size_gb=400)]))))

    def test_img004_emulated_launch(self):
        self.assertIn("IMG004", rule_ids(audit_document(doc([base_image(launch_mode="EMULATED")]))))

    def test_img005_too_many_versions(self):
        images = [base_image(name=f"web-v{i}") for i in range(5)]
        self.assertIn("IMG005", rule_ids(audit_document(doc(images))))

    def test_img005_within_keep_count_ok(self):
        images = [base_image(name=f"web-v{i}") for i in range(3)]
        self.assertNotIn("IMG005", rule_ids(audit_document(doc(images))))

    def test_img006_missing_owner_tag(self):
        self.assertIn("IMG006", rule_ids(audit_document(doc([base_image(tags={})]))))

    def test_findings_sorted_high_first(self):
        image = base_image(operating_system_version="6.10",  # IMG002 HIGH
                           launch_mode="EMULATED")           # IMG004 LOW
        findings = audit_document(doc([image]))
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "LOW")

    def test_non_dict_entries_skipped(self):
        findings = audit_document({"reference_time": REF, "images": [None, "junk", base_image()]})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
