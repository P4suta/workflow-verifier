import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_CONFIG = Path(".github/renovate.json")
# `configFileNames` in Renovate's `config/app-strings`, without `package.json`, which this repository lacks.
HOSTED_CONFIG_NAMES = tuple(
    f"{stem}{suffix}"
    for stem in ("renovate.json", ".github/renovate.json", ".gitlab/renovate.json")
    for suffix in ("", "c", "5")
) + (".renovaterc", ".renovaterc.json", ".renovaterc.jsonc", ".renovaterc.json5")
FROZEN_INPUTS = ("evaluation/corpus/**", "fuzz/corpus/**", "test/fixtures/**")
# A repository `ignorePaths` replaces the list from `:ignoreModulesAndTests` in `config:recommended`.
PRESET_IGNORE_PATHS = (
    "**/node_modules/**",
    "**/bower_components/**",
    "**/vendor/**",
    "**/examples/**",
    "**/__tests__/**",
    "**/test/**",
    "**/tests/**",
    "**/__fixtures__/**",
)


def _ignore_paths(relative: Path) -> list[str]:
    document = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    paths = document["ignorePaths"]
    assert isinstance(paths, list)
    return [str(path) for path in paths]


class RenovateConfigTests(unittest.TestCase):
    def test_hosted_renovate_reads_exactly_one_repository_config(self) -> None:
        present = [name for name in HOSTED_CONFIG_NAMES if (ROOT / name).is_file()]
        self.assertEqual(present, [REPOSITORY_CONFIG.as_posix()])

    def test_repository_config_extends_the_shared_preset(self) -> None:
        document = json.loads((ROOT / REPOSITORY_CONFIG).read_text(encoding="utf-8"))
        self.assertEqual(document["extends"], ["github>P4suta/renovate-config"])

    def test_dependency_automation_never_edits_frozen_inputs(self) -> None:
        for relative in (REPOSITORY_CONFIG, Path("renovate.local.json5")):
            with self.subTest(config=relative.as_posix()):
                paths = _ignore_paths(relative)
                for pattern in (*FROZEN_INPUTS, *PRESET_IGNORE_PATHS):
                    self.assertIn(pattern, paths)


if __name__ == "__main__":
    unittest.main()
