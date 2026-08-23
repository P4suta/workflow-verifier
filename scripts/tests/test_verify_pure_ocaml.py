from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "verify_pure_ocaml.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("verify_pure_ocaml", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load purity checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OpamDependencyParserTests(unittest.TestCase):
    def test_versions_and_filter_values_are_not_dependency_names(self) -> None:
        checker = load_checker()
        source = '''
depends: [
  "ocaml" {>= "5.4" & < "5.6"}
  "dune" {>= "3.21"}
  "odoc" {with-doc}
]
'''
        self.assertEqual(
            checker.opam_dependency_names(source),
            {"ocaml", "dune", "odoc"},
        )

    def test_missing_dependency_stanza_is_rejected(self) -> None:
        checker = load_checker()
        with self.assertRaises(ValueError):
            checker.opam_dependency_names('opam-version: "2.0"')


if __name__ == "__main__":
    unittest.main()
