from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def section(source: str, start: str, stop: str) -> str:
    return source.split(start, 1)[1].split(stop, 1)[0]


class RustFirstSurfaceTests(unittest.TestCase):
    def test_workspace_has_one_public_crate_and_seven_private_packages(self) -> None:
        self.assertTrue((ROOT / "Cargo.lock").is_file())
        self.assertFalse((ROOT / "helpers" / "Cargo.lock").exists())
        root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        members = root_manifest["workspace"]["members"]
        self.assertEqual(len(members), 8)
        self.assertEqual(members[0], ".")
        private_manifests = [ROOT / member / "Cargo.toml" for member in members[1:]]
        self.assertEqual(len(private_manifests), 7)
        for manifest in private_manifests:
            self.assertIn("publish = false", manifest.read_text(encoding="utf-8"), manifest)
        self.assertEqual(root_manifest["package"]["name"], "workflow-verifier")
        self.assertNotEqual(root_manifest["package"].get("publish"), False)
        for dependency in root_manifest.get("dependencies", {}).values():
            self.assertNotIn("path", dependency)

    def test_ci_treats_rust_as_the_product_on_all_release_platforms(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        product = section(ci, "  rust-product:\n", "  ocaml-reference:\n")
        for platform in (
            "linux-x86_64",
            "linux-arm64",
            "windows-x86_64",
            "macos-arm64",
            "macos-x86_64",
        ):
            self.assertIn(f"platform: {platform}", product)
        self.assertIn("cargo test --locked --workspace --all-targets", product)
        self.assertIn("cargo fmt --all -- --check", product)
        self.assertIn("cargo clippy --workspace --all-targets -- -D warnings", product)
        self.assertIn("cargo audit --file Cargo.lock --deny warnings", ci)
        self.assertNotIn("helpers/Cargo.lock", ci)

    def test_workflows_use_only_the_repository_pinned_rust_setup(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        workflow_sources = {
            workflow.relative_to(ROOT).as_posix(): workflow.read_text(encoding="utf-8")
            for workflow in workflows
        }
        for relative, source in workflow_sources.items():
            self.assertNotIn("actions-rust-lang/setup-rust-toolchain", source, relative)
            self.assertNotIn("Swatinem/rust-cache", source, relative)

        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/official-compat.yml",
            ".github/workflows/candidate.yml",
        ):
            self.assertIn(
                "uses: ./.github/actions/setup-repository-rust",
                workflow_sources[relative],
                relative,
            )

        setup = (ROOT / ".github" / "actions" / "setup-repository-rust" / "action.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("rustup show active-toolchain", setup)
        self.assertIn("rustc --version --verbose", setup)
        self.assertIn("cargo --version --verbose", setup)
        self.assertNotIn("uses:", setup)

    def test_os_credential_service_constant_is_compiled_only_where_it_is_used(self) -> None:
        auth = (ROOT / "src" / "application" / "auth.rs").read_text(encoding="utf-8")
        self.assertIn(
            '#[cfg(any(target_os = "macos", test))]\n'
            'const CREDENTIAL_SERVICE: &str = "workflow-verifier";',
            auth,
        )

    def test_dependency_policy_names_every_reviewed_transport_license(self) -> None:
        policy = (ROOT / "deny.toml").read_text(encoding="utf-8")
        for license_id in ("BSD-3-Clause", "ISC", "MIT-0", "Unicode-3.0"):
            self.assertIn(f'  "{license_id}",', policy)
        self.assertIn(
            '{ name = "syn", version = "=2.0.119" }',
            policy,
        )

    def test_live_and_official_product_gates_execute_the_rust_cli(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        dogfood = section(ci, "  live-dogfood:\n", "  official-compat:\n")
        official = section(ci, "  official-compat:\n", "  rust-performance-regression:\n")
        for gate in (dogfood, official):
            self.assertIn("cargo build --locked -p workflow-verifier", gate)
            self.assertIn("target/debug/workflow-verifier", gate)
            self.assertNotIn("_build/default/bin/main.exe", gate)
        reference = section(ci, "  ocaml-reference:\n", "  linux-native-containment:\n")
        self.assertIn("just differential", reference)
        self.assertNotIn("workflow-verifier-reference check", reference)

    def test_rust_performance_baseline_selects_the_stable_binary_name(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        performance = section(ci, "  rust-performance-regression:\n", "  yaml-fuzz-corpus:\n")
        self.assertIn("--manifest-path _performance-base/Cargo.toml", performance)
        self.assertIn("--bin workflow-verifier", performance)

        justfile = (ROOT / "justfile").read_text(encoding="utf-8")
        mise = (ROOT / "mise.toml").read_text(encoding="utf-8")
        for source in (justfile, mise):
            self.assertIn("--manifest-path", source)
            self.assertIn("--bin workflow-verifier", source)

    def test_public_local_tasks_default_to_rust_and_keep_reference_in_differential_only(
        self,
    ) -> None:
        justfile = (ROOT / "justfile").read_text(encoding="utf-8")
        mise = (ROOT / "mise.toml").read_text(encoding="utf-8")
        for source in (justfile, mise):
            self.assertIn("target/debug/workflow-verifier", source)
            self.assertIn("target/debug/workflow-verifier check --config", source)
            dogfood = source.split("dogfood", 1)[1]
            self.assertNotIn("dune exec workflow-verifier --", dogfood)
        self.assertIn("_build/default/bin/main.exe", justfile.split("differential:", 1)[1])

    def test_user_documentation_is_english_rust_first_and_uses_current_contracts(self) -> None:
        self.assertEqual(list((ROOT / "docs").glob("*.ja.md")), [])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Rust product", readme)
        self.assertIn("workflow-verifier-reference", readme)
        self.assertIn("report.json", readme)
        self.assertIn("workflow-verifier-report/1", readme)
        self.assertIn("release-evidence-v4", readme)
        self.assertIn("workflow-verifier lsp", readme)
        self.assertIn("uses: P4suta/workflow-verifier@", readme)
        for relative in (
            "README.md",
            "docs/evaluation.md",
            "docs/release.md",
            "docs/release-notes-v0.1.0.md",
            "docs/security-review.md",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("release-evidence-v3", source, relative)


if __name__ == "__main__":
    unittest.main()
