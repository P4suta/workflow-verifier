from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_licenses.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("verify_licenses", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load license checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LicenseSurfaceTests(unittest.TestCase):
    def test_repository_license_surface_is_complete_and_consistent(self) -> None:
        checker = load_checker()
        self.assertEqual(checker.validate(ROOT), [])

    def test_truncated_apache_notice_is_rejected(self) -> None:
        checker = load_checker()
        truncated = """Apache License
Version 2.0, January 2004
TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
END OF TERMS AND CONDITIONS
"""
        failures = checker.validate_apache(truncated)
        self.assertTrue(any("section 1" in failure for failure in failures))
        self.assertTrue(any("appendix" in failure for failure in failures))

    def test_spdx_expression_must_be_exact(self) -> None:
        checker = load_checker()
        self.assertTrue(checker.has_exact_spdx('(license "MIT OR Apache-2.0")'))
        self.assertTrue(checker.has_exact_spdx('license: "MIT OR Apache-2.0"'))
        self.assertFalse(checker.has_exact_spdx('(license "MIT")'))
        self.assertFalse(checker.has_exact_spdx('license: "Apache-2.0")'))


if __name__ == "__main__":
    unittest.main()
