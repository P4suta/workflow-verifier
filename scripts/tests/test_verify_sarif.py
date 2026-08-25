from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None


@unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema is installed by the pinned quality lock")
class SarifSchemaTests(unittest.TestCase):
    def test_digest_identity_and_document_validation_are_fail_closed(self) -> None:
        from scripts.verify_sarif import DRAFT4_SCHEMA_ID, OASIS_SCHEMA_ID, verify

        schema = {
            "$schema": DRAFT4_SCHEMA_ID,
            "additionalProperties": False,
            "id": OASIS_SCHEMA_ID,
            "properties": {
                "$schema": {"enum": [OASIS_SCHEMA_ID]},
                "runs": {"type": "array"},
                "version": {"enum": ["2.1.0"]},
            },
            "required": ["version", "runs"],
            "type": "object",
        }
        document = {"$schema": OASIS_SCHEMA_ID, "runs": [], "version": "2.1.0"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema_path = root / "sarif-schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            digest = "sha256:" + hashlib.sha256(schema_path.read_bytes()).hexdigest()
            document_path = root / "report.sarif.json"
            document_path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(verify(schema_path, digest, [document_path]), 1)

            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                verify(schema_path, "sha256:" + "0" * 64, [document_path])

            document["unexpected"] = True
            document_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Additional properties"):
                verify(schema_path, digest, [document_path])

    def test_duplicate_document_keys_are_rejected(self) -> None:
        from scripts.verify_sarif import DRAFT4_SCHEMA_ID, OASIS_SCHEMA_ID, verify

        schema = {
            "$schema": DRAFT4_SCHEMA_ID,
            "id": OASIS_SCHEMA_ID,
            "properties": {"$schema": {"type": "string"}, "runs": {"type": "array"}},
            "required": ["runs"],
            "type": "object",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema_path = root / "sarif-schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            digest = "sha256:" + hashlib.sha256(schema_path.read_bytes()).hexdigest()
            document_path = root / "report.sarif.json"
            document_path.write_text(
                f'{{"$schema":"{OASIS_SCHEMA_ID}","runs":[],"runs":[]}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON field runs"):
                verify(schema_path, digest, [document_path])


if __name__ == "__main__":
    unittest.main()
