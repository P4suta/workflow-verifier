from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EXCLUDED_SOURCES = [
    "build.rs",
    "crates/**",
    "helpers/**",
    "src/application/**",
    "src/conformance/**",
    "src/helper_runtime/**",
    "src/internal.rs",
    "src/lib.rs",
    "src/main.rs",
]

SEMANTIC_TEST_PACKAGES = [
    "workflow-verifier",
    "workflow-verifier-conformance",
]

HIGH_VALUE_LAYERS = [
    "domain",
    "engine",
    "foundation",
    "frontend",
    "product",
    "sandbox",
    "syntax",
    "verifier",
    "runner_protocol",
]


class RustMutationScopeTests(unittest.TestCase):
    def test_scope_is_explicitly_limited_to_product_semantics(self) -> None:
        with (ROOT / ".cargo" / "mutants.toml").open("rb") as source:
            config = tomllib.load(source)

        self.assertEqual(config["exclude_globs"], EXCLUDED_SOURCES)
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
        excluded = "\n".join(config["exclude_globs"])
        self.assertIn("src/application", excluded)
        self.assertNotIn("src/runner_protocol", excluded)
        self.assertIn("src/helper_runtime", excluded)

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
        self.assertIn("--package workflow-verifier", rust_job)
        self.assertIn('--file "src/$MUTATION_LAYER/**/*.rs"', rust_job)
        for layer in HIGH_VALUE_LAYERS:
            self.assertRegex(rust_job, rf"(?m)^\s+- {re.escape(layer)}$")
        self.assertNotIn("workflow-verifier-cli", workflow)


if __name__ == "__main__":
    unittest.main()
