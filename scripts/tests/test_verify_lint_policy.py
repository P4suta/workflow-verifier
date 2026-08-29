from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "verify_lint_policy.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("verify_lint_policy", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load lint-policy checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rust_errors(source: str) -> list[str]:
    checker = load_checker()
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        path = root / "src" / "lib.rs"
        path.parent.mkdir(parents=True)
        path.write_text(source, encoding="utf-8")
        return checker.rust_source_errors(root)


class LintPolicyTests(unittest.TestCase):
    def test_inner_outer_and_cfg_allow_attributes_are_rejected(self) -> None:
        for source in (
            "#![allow(dead_code)]\n",
            "#[allow(dead_code)]\nfn hidden() {}\n",
            "#[cfg_attr(test, allow(dead_code))]\nfn hidden() {}\n",
        ):
            self.assertTrue(rust_errors(source), source)

    def test_expect_needs_a_reason_and_may_not_name_a_group(self) -> None:
        self.assertTrue(rust_errors("#[expect(dead_code)]\nfn hidden() {}\n"))
        for lint_group in (
            "deprecated_safe",
            "unknown_or_malformed_diagnostic_attributes",
            "clippy::pedantic",
        ):
            with self.subTest(lint_group=lint_group):
                self.assertTrue(
                    rust_errors(f'#[expect({lint_group}, reason = "too broad")]\nfn item() {{}}\n')
                )
        self.assertEqual(
            rust_errors('#[expect(dead_code, reason = "contract fixture")]\nfn hidden() {}\n'),
            [],
        )

    def test_manifest_lint_allow_is_rejected(self) -> None:
        checker = load_checker()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "Cargo.toml").write_text(
                '[package]\nname="fixture"\nversion="0.1.0"\n[lints.rust]\ndead_code="allow"\n',
                encoding="utf-8",
            )
            self.assertTrue(
                any("explicit lint allow" in error for error in checker.manifest_errors(root))
            )

    def test_first_party_rust_allow_flag_is_rejected(self) -> None:
        checker = load_checker()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / ".cargo" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text('rustflags = ["-A", "dead_code"]\n', encoding="utf-8")
            self.assertTrue(checker.first_party_flag_errors(root))

    def test_compiler_rejects_an_unfulfilled_expectation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "fixture.rs"
            source.write_text(
                '#![expect(dead_code, reason = "negative contract")]\npub fn visible() {}\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "rustc",
                    "--crate-type",
                    "lib",
                    "--edition",
                    "2024",
                    "-D",
                    "unfulfilled-lint-expectations",
                    str(source),
                    "-o",
                    str(root / "fixture.rlib"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unfulfilled", result.stderr)


if __name__ == "__main__":
    unittest.main()
