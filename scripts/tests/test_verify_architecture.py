from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "verify_architecture.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("verify_architecture", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load architecture checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuneArchitectureTests(unittest.TestCase):
    def test_library_parser_retains_modules_and_dependencies(self) -> None:
        checker = load_checker()
        library = checker.parse_library(
            "lib/example/dune",
            """
(library
 (name wv_example)
 (wrapped false)
 (modules alpha beta)
 (libraries wv_foundation wv_domain))
""",
        )
        self.assertEqual(library.name, "wv_example")
        self.assertEqual(library.modules, ("alpha", "beta"))
        self.assertEqual(library.dependencies, ("wv_foundation", "wv_domain"))
        self.assertFalse(library.wrapped)

    def test_dependency_inversion_is_rejected(self) -> None:
        checker = load_checker()
        actual = dict(checker.EXPECTED_DEPENDENCIES)
        actual["wv_foundation"] = ("wv_product",)
        errors = checker.validate_dependencies(actual)
        self.assertTrue(any("wv_foundation" in error for error in errors))

    def test_cycle_is_rejected_even_when_every_name_is_known(self) -> None:
        checker = load_checker()
        actual = {
            "wv_foundation": ("wv_domain",),
            "wv_domain": ("wv_foundation",),
        }
        self.assertTrue(any("cycle" in error for error in checker.graph_errors(actual)))


if __name__ == "__main__":
    unittest.main()
