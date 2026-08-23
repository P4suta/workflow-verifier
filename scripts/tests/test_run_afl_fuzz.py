from pathlib import Path
import tempfile
import unittest

from scripts.run_afl_fuzz import build_command, validate_results


class RunAflFuzzTests(unittest.TestCase):
    def result_tree(self, root: Path) -> Path:
        queue = root / "default" / "queue"
        crashes = root / "default" / "crashes"
        hangs = root / "default" / "hangs"
        queue.mkdir(parents=True)
        crashes.mkdir()
        hangs.mkdir()
        (queue / "id:000000").write_bytes(b"seed")
        (crashes / "README.txt").write_text("metadata", encoding="utf-8")
        (hangs / "README.txt").write_text("metadata", encoding="utf-8")
        (root / "default" / "fuzzer_stats").write_text(
            "execs_done        : 1234\ncorpus_count      : 17\n",
            encoding="utf-8",
        )
        return root

    def test_completed_campaign_requires_executions_and_no_crashes_or_hangs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stats = validate_results(self.result_tree(Path(temporary)))
            self.assertEqual(stats["execs_done"], 1234)
            self.assertEqual(stats["corpus_count"], 17)

    def test_any_crash_or_hang_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.result_tree(Path(temporary))
            (root / "default" / "crashes" / "id:000001").write_bytes(b"boom")
            with self.assertRaisesRegex(ValueError, "one crashing input"):
                validate_results(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.result_tree(Path(temporary))
            (root / "default" / "hangs" / "id:000001").write_bytes(b"hang")
            with self.assertRaisesRegex(ValueError, "one hanging input"):
                validate_results(root)

    def test_command_is_an_argv_vector_with_afl_placeholder(self) -> None:
        command = build_command(
            Path("/usr/bin/afl-fuzz"),
            Path("seeds"),
            Path("results"),
            Path("yaml_fuzz.exe"),
            seconds=60,
            memory_mb=1024,
        )
        self.assertEqual(command[0], "/usr/bin/afl-fuzz")
        self.assertIn("@@", command)
        self.assertEqual(command[-3:], ["yaml_fuzz.exe", "--input", "@@"])
        self.assertNotIn("sh", command)


if __name__ == "__main__":
    unittest.main()
