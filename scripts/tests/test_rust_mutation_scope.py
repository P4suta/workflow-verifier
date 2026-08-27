from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

HIGH_VALUE_SOURCES = [
    "crates/domain/src/**/*.rs",
    "crates/engine/src/**/*.rs",
    "crates/foundation/src/**/*.rs",
    "crates/frontend/src/**/*.rs",
    "crates/product/src/**/*.rs",
    "crates/sandbox/src/**/*.rs",
    "crates/syntax/src/**/*.rs",
    "crates/verifier/src/**/*.rs",
    "helpers/protocol/src/**/*.rs",
]

SEMANTIC_TEST_PACKAGES = [
    "workflow-verifier-conformance",
    "workflow-verifier-domain",
    "workflow-verifier-engine",
    "workflow-verifier-foundation",
    "workflow-verifier-frontend",
    "workflow-verifier-product",
    "workflow-verifier-sandbox",
    "workflow-verifier-syntax",
    "workflow-verifier-verifier",
    "workflow-verifier-runner-protocol",
]


class RustMutationScopeTests(unittest.TestCase):
    def test_scope_is_explicitly_limited_to_product_semantics(self) -> None:
        with (ROOT / ".cargo" / "mutants.toml").open("rb") as source:
            config = tomllib.load(source)

        self.assertEqual(config["examine_globs"], HIGH_VALUE_SOURCES)
        self.assertEqual(config["test_package"], SEMANTIC_TEST_PACKAGES)
        self.assertEqual(config["profile"], "mutants")
        self.assertEqual(config["test_tool"], "cargo")
        self.assertTrue(config["cap_lints"])
        self.assertEqual(config["exclude_re"], ["helper_main"])
        for runner_owned_default in (
            "build_timeout_multiplier",
            "timeout_multiplier",
            "minimum_test_timeout",
        ):
            self.assertNotIn(runner_owned_default, config)
        self.assertNotIn("crates/cli", "\n".join(config["examine_globs"]))
        self.assertIn("helpers/protocol", "\n".join(config["examine_globs"]))
        self.assertNotIn("helpers/runtime", "\n".join(config["examine_globs"]))

        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            workspace["profile"]["mutants"],
            {"inherits": "test", "debug": "none"},
        )

    def test_local_and_hosted_commands_pin_the_same_runner_and_scope(self) -> None:
        justfile = (ROOT / "justfile").read_text(encoding="utf-8")
        mise = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))
        workflow = (ROOT / ".github/workflows/mutation.yml").read_text(encoding="utf-8")

        for task in ("mutation-rust-list", "mutation-rust", "mutation-rust-high-value"):
            self.assertRegex(justfile, rf"(?m)^{re.escape(task)}(?:\s+[^:]*)?:$")
            self.assertIn(task, mise["tasks"])
        for source in (justfile, workflow):
            self.assertIn("--config .cargo/mutants.toml", source)
        rust_job = workflow.split("  rust-high-value:\n", 1)[1].split("\n  catalog:\n", 1)[0]
        self.assertNotIn("--build-timeout", justfile)
        self.assertNotIn("--build-timeout", rust_job)
        self.assertNotIn("--jobs", rust_job)
        self.assertNotIn("timeout-minutes", rust_job)
        for task in ("mutation-rust", "mutation-rust-high-value"):
            run = mise["tasks"][task]["run"]
            self.assertNotIn("--build-timeout", run)
            self.assertNotIn("--jobs", run)
        self.assertIn("cargo-mutants --version 27.1.0 --locked", workflow)
        self.assertIn("rust-high-value", workflow)
        for package in SEMANTIC_TEST_PACKAGES[1:]:
            self.assertIn(package, workflow)
        self.assertNotIn("- workflow-verifier-cli", workflow)


if __name__ == "__main__":
    unittest.main()
