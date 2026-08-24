from __future__ import annotations

import importlib.util
import pathlib
import tempfile
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

    def test_partial_assertions_are_rejected_from_analyzer_libraries(self) -> None:
        checker = load_checker()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "lib" / "example.ml"
            source.parent.mkdir(parents=True)
            source.write_text(
                "let decode = function Some value -> value | None -> assert false\n",
                encoding="utf-8",
            )

            self.assertEqual(
                checker.partial_expression_errors(root),
                ["lib/example.ml contains partial expression 'assert false'"],
            )

    def test_partial_stdlib_and_exception_escapes_are_rejected(self) -> None:
        checker = load_checker()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "lib" / "example.ml"
            source.parent.mkdir(parents=True)
            source.write_text(
                "let first values = List.hd values\n"
                "let require value = invalid_arg value\n",
                encoding="utf-8",
            )

            self.assertEqual(
                checker.partial_expression_errors(root),
                [
                    "lib/example.ml contains partial expression 'List.hd'",
                    "lib/example.ml contains partial expression 'invalid_arg'",
                ],
            )


if __name__ == "__main__":
    unittest.main()
