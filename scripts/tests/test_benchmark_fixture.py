import tempfile
import unittest
from pathlib import Path

from scripts.benchmark_fixture import prepare


class BenchmarkFixtureTests(unittest.TestCase):
    def test_reset_and_toggle_create_four_provider_workload_with_one_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = prepare(workspace, "reset")
            expected = {
                ".circleci/config.yml",
                ".github/workflows/ci.yml",
                ".gitlab-ci.yml",
                ".workflow-verifier.toml",
                "azure-pipelines.yml",
            }
            self.assertEqual(
                {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()},
                expected,
            )
            before = {name: (root / name).read_bytes() for name in expected}
            prepare(workspace, "toggle")
            after = {name: (root / name).read_bytes() for name in expected}
            changed = [name for name in expected if before[name] != after[name]]
            self.assertEqual(changed, [".github/workflows/ci.yml"])
            prepare(workspace, "toggle")
            self.assertEqual((root / ".github/workflows/ci.yml").read_bytes(), before[".github/workflows/ci.yml"])

    def test_rejects_symlinked_or_unknown_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with self.assertRaisesRegex(ValueError, "mode"):
                prepare(workspace, "delete")
            outside = workspace / "outside"
            outside.mkdir()
            build = workspace / "_build"
            try:
                build.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "symlink"):
                prepare(workspace, "reset")

    def test_arcade_scale_fixture_is_large_deterministic_and_single_delta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = prepare(workspace, "reset", "arcade-scale")
            pipeline = root / "azure-pipelines.yml"
            before = pipeline.read_bytes()
            self.assertGreater(len(before), 120_000)
            self.assertEqual(before.count(b"repository: dependency_"), 64)
            self.assertEqual(before.count(b"environment: production-"), 28)
            self.assertEqual(before.count(b"- stage:"), 29)
            prepare(workspace, "toggle", "arcade-scale")
            after = pipeline.read_bytes()
            self.assertEqual(len(before), len(after))
            self.assertNotEqual(before, after)
            prepare(workspace, "toggle", "arcade-scale")
            self.assertEqual(pipeline.read_bytes(), before)

            with self.assertRaisesRegex(ValueError, "scenario"):
                prepare(workspace, "reset", "unknown")


if __name__ == "__main__":
    unittest.main()
