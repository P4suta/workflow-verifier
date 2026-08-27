from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.prepare_corpus import (
    Candidate,
    GitHubSource,
    Snapshot,
    acquire,
    analyzer_command,
    apply_review,
    rebase_review,
    refresh,
)

PROVIDERS = ("github", "gitlab", "azure", "circleci")
WORKFLOW_PATHS = {
    "github": ".github/workflows/ci.yml",
    "gitlab": ".gitlab-ci.yml",
    "azure": "azure-pipelines.yml",
    "circleci": ".circleci/config.yml",
}


def diagnostic(identifier: str, rule_id: str) -> dict[str, object]:
    return {
        "capabilities": [],
        "confidence": "high",
        "evidence": [],
        "fix": None,
        "id": identifier,
        "message": "review me",
        "rule_id": rule_id,
        "severity": "warning",
        "span": {
            "file": ".github/workflows/ci.yml",
            "start": {"byte": 0, "column": 1, "line": 1},
            "stop": {"byte": 1, "column": 2, "line": 1},
        },
        "trace": [],
    }


def seal(document: dict[str, object]) -> dict[str, object]:
    document.pop("digest", None)
    document.pop("semantic_digest", None)
    semantic = json.loads(json.dumps(document))
    semantic["tool"].pop("build")
    document["semantic_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(semantic, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    document["digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    return document


def report(diagnostics: list[dict[str, object]]) -> dict[str, object]:
    digest = "sha256:" + "f" * 64
    return seal(
        {
            "completeness": {"reasons": [], "state": "complete"},
            "configuration": {"digest": digest, "origin": "built-in", "trust": "built-in"},
            "diagnostics": diagnostics,
            "gate": {"exit_code": 0, "result": "pass"},
            "graphs": [],
            "inputs": [],
            "lock": {"digest": digest},
            "persona": "audit",
            "provider_profiles": [],
            "properties": [],
            "schema": "report-v3",
            "snapshot": {"digest": digest, "schema": "source-manifest-v2"},
            "summary": {
                "diagnostics": len(diagnostics),
                "graphs": 0,
                "inputs": 0,
                "unknown_properties": 0,
            },
            "tool": {
                "build": {
                    "binary_digest": digest,
                    "compiler": "rustc test",
                    "implementation": "rust",
                    "source_commit": "a" * 40,
                    "target": "test-target",
                },
                "name": "workflow-verifier",
                "version": "0.1.0",
            },
        }
    )


def legacy_report(diagnostics: list[dict[str, object]]) -> dict[str, object]:
    document = report(diagnostics)
    for field in (
        "completeness",
        "configuration",
        "gate",
        "lock",
        "provider_profiles",
        "snapshot",
    ):
        document.pop(field)
    document.pop("semantic_digest")
    document["schema"] = "report-v1"
    document["tool"] = {
        "binary_digest": "sha256:" + "f" * 64,
        "build": {"dune": "3.24.2", "ocaml": "5.5.0", "source_commit": "a" * 40},
        "name": "workflow-verifier",
        "version": "0.1.0",
    }
    document["digest"] = None
    document["digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    return document


class FakeSource:
    def candidates(self, provider: str):
        yield Candidate(
            provider=provider,
            full_name=f"Acme/{provider}-project",
            workflow_path=WORKFLOW_PATHS[provider],
        )

    def fetch(self, candidate: Candidate) -> Snapshot:
        index = PROVIDERS.index(candidate.provider) + 1
        return Snapshot(
            license_bytes=b"MIT fixture license\n",
            license_expression="MIT",
            license_path="LICENSE",
            revision=f"{index:040x}",
            url=f"https://github.com/{candidate.full_name}.git",
            workflow_bytes=f"name: {candidate.provider}\n".encode(),
            workflow_path=candidate.workflow_path,
        )


class FakeGitHubSource(GitHubSource):
    def __init__(self) -> None:
        super().__init__("fixture-token", pages=1)

    def _request(self, path: str, parameters: dict[str, str] | None = None):
        if path == "search/code":
            return {
                "items": [
                    {
                        "path": ".gitlab-ci.yml",
                        "repository": {"full_name": "Acme/Project"},
                    },
                    {
                        "path": ".gitlab-ci.yml",
                        "repository": {"full_name": "acme/project"},
                    },
                    {
                        "path": "nested/.gitlab-ci.yml",
                        "repository": {"full_name": "Acme/Ignored"},
                    },
                    {
                        "path": ".gitlab-ci.yml",
                        "repository": {"full_name": "../escape"},
                    },
                ]
            }
        if path == "repos/Acme/Project":
            return {
                "archived": False,
                "default_branch": "main",
                "disabled": False,
                "fork": False,
                "html_url": "https://github.com/Acme/Project",
                "license": {"spdx_id": "MIT"},
            }
        if path == "repos/Acme/Project/commits/main":
            return {"sha": "a" * 40}
        if path == "repos/Acme/Project/contents/.gitlab-ci.yml":
            return {
                "content": base64.encodebytes(b"stages: [test]\n").decode(),
                "encoding": "base64",
                "type": "file",
            }
        if path == "repos/Acme/Project/license":
            return {
                "content": base64.encodebytes(b"MIT license\n").decode(),
                "encoding": "base64",
                "license": {"spdx_id": "MIT"},
                "path": "LICENSE",
                "type": "file",
            }
        raise AssertionError((path, parameters))


class CorpusPreparationTests(unittest.TestCase):
    def test_acquisition_failure_never_cleans_an_unvalidated_repository_path(self) -> None:
        class TraversalSource:
            def candidates(self, provider: str):
                if provider == "github":
                    yield Candidate(
                        provider=provider,
                        full_name="../../../victim",
                        workflow_path=WORKFLOW_PATHS[provider],
                    )

            def fetch(self, candidate: Candidate) -> Snapshot:
                return FakeSource().fetch(candidate)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "victim" / "keep.txt"
            marker.parent.mkdir()
            marker.write_text("must survive\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "could not acquire"):
                acquire(
                    TraversalSource(),
                    lambda _checkout: report([]),
                    root / "evaluation",
                    per_provider=1,
                )

            self.assertEqual(marker.read_text(encoding="utf-8"), "must survive\n")

    def test_analyzer_uses_corpus_relative_paths_in_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analyzer = root / "workflow-verifier.exe"
            analyzer.write_bytes(b"fixture")
            corpus_root = root / ".random-staging" / "corpus"
            checkout = corpus_root / "github" / "acme" / "project"
            checkout.mkdir(parents=True)
            completed = type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stderr": b"",
                    "stdout": json.dumps(report([])).encode(),
                },
            )()
            with patch("scripts.prepare_corpus.subprocess.run", return_value=completed) as run:
                analyzer_command(analyzer)(checkout)
            argv = run.call_args.args[0]
            working_directory = Path(run.call_args.kwargs["cwd"])
            self.assertEqual(working_directory, corpus_root)
            self.assertEqual(Path(argv[-1]), Path("github/acme/project"))

    def test_github_adapter_deduplicates_search_and_pins_source_bytes(self) -> None:
        source = FakeGitHubSource()
        candidates = list(source.candidates("gitlab"))
        self.assertEqual(candidates, [Candidate("gitlab", "Acme/Project", ".gitlab-ci.yml")])
        snapshot = source.fetch(candidates[0])
        self.assertEqual(snapshot.revision, "a" * 40)
        self.assertEqual(snapshot.workflow_bytes, b"stages: [test]\n")
        self.assertEqual(snapshot.license_bytes, b"MIT license\n")

    def test_acquisition_is_immutable_canonical_and_review_is_exhaustive(self) -> None:
        finding = diagnostic("diag_" + "1" * 20, "WV-SEC-001")

        def analyze(checkout: Path) -> dict[str, object]:
            provider = checkout.parts[-3]
            return report([finding] if provider == "github" else [])

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evaluation"
            manifest = acquire(FakeSource(), analyze, output, per_provider=1)

            self.assertEqual(manifest["schema"], "corpus-v1")
            self.assertEqual(
                [item["provider"] for item in manifest["repositories"]],
                list(PROVIDERS),
            )
            self.assertTrue(all(len(item["revision"]) == 40 for item in manifest["repositories"]))
            self.assertTrue(
                all(
                    item["source_digest"].startswith("sha256:") for item in manifest["repositories"]
                )
            )
            draft = json.loads((output / "review-draft-v1.json").read_text(encoding="utf-8"))
            self.assertEqual(draft["repositories"][0]["diagnostics"][0]["id"], finding["id"])

            review_path = output / "review-v1.json"
            review_path.write_text(
                json.dumps(
                    {
                        "repositories": [
                            {
                                "diagnostics": [
                                    {
                                        "classification": "expected",
                                        "id": finding["id"],
                                        "reason": "Untrusted input reaches a shell command without quoting.",
                                        "rule_id": finding["rule_id"],
                                    }
                                ],
                                "id": "github/acme/github-project",
                            }
                        ],
                        "schema": "corpus-review-v1",
                    }
                ),
                encoding="utf-8",
            )
            reviewed = apply_review(output / "corpus-v1.json", output / "reports", review_path)
            github = next(item for item in reviewed["repositories"] if item["provider"] == "github")
            self.assertEqual(
                github["expected_diagnostics"],
                [{"id": finding["id"], "rule_id": finding["rule_id"]}],
            )
            self.assertEqual(github["allowed_diagnostics"], [])

    def test_review_rejects_missing_and_mismatched_diagnostics(self) -> None:
        finding = diagnostic("diag_" + "2" * 20, "WV-AUTH-001")

        def analyze(_checkout: Path) -> dict[str, object]:
            return report([finding])

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evaluation"
            acquire(FakeSource(), analyze, output, per_provider=1)
            review_path = output / "review-v1.json"
            review_path.write_text(
                '{"repositories":[],"schema":"corpus-review-v1"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unreviewed diagnostic"):
                apply_review(output / "corpus-v1.json", output / "reports", review_path)

            review_path.write_text(
                json.dumps(
                    {
                        "repositories": [
                            {
                                "diagnostics": [
                                    {
                                        "classification": "allowed",
                                        "id": finding["id"],
                                        "reason": "Reviewed semantic exception with preserved authorization.",
                                        "rule_id": "WV-WRONG-001",
                                    }
                                ],
                                "id": "github/acme/github-project",
                            }
                        ],
                        "schema": "corpus-review-v1",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "rule mismatch"):
                apply_review(output / "corpus-v1.json", output / "reports", review_path)

    def test_refresh_reanalyzes_immutable_snapshots_without_network(self) -> None:
        finding = diagnostic("diag_" + "3" * 20, "WV-SUPPLY-001")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "evaluation"
            original = acquire(FakeSource(), lambda _checkout: report([]), current, per_provider=1)
            refreshed_path = root / "evaluation-refreshed"
            refreshed = refresh(
                current,
                lambda _checkout: report([finding]),
                refreshed_path,
                workers=2,
            )
            self.assertEqual(
                [item["source_digest"] for item in refreshed["repositories"]],
                [item["source_digest"] for item in original["repositories"]],
            )
            self.assertTrue(
                all(not item["expected_diagnostics"] for item in refreshed["repositories"])
            )
            draft = json.loads(
                (refreshed_path / "review-draft-v1.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(draft["repositories"]), len(PROVIDERS))
            self.assertTrue(
                all(item["diagnostics"][0]["id"] == finding["id"] for item in draft["repositories"])
            )
            self.assertTrue((current / "reports").is_dir())

    def test_review_rebase_is_explicit_bijective_and_semantic(self) -> None:
        old_finding = diagnostic("diag_" + "4" * 20, "WV-SUPPLY-001")
        old_finding["trace"] = [
            {
                "label": "mutable dependency",
                "node_id": "wv_old",
                "span": {
                    "file": ".github/workflows/ci.yml",
                    "start": {"byte": 40, "column": 4, "line": 3},
                    "stop": {"byte": 50, "column": 14, "line": 3},
                },
            }
        ]
        new_finding = json.loads(json.dumps(old_finding))
        new_finding["id"] = "diag_" + "5" * 20
        new_finding["trace"][0]["node_id"] = "wv_new"
        new_finding["trace"][0]["span"]["start"]["byte"] = 80
        new_finding["trace"][0]["span"]["stop"]["byte"] = 90

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "evaluation"
            manifest = acquire(
                FakeSource(),
                lambda _checkout: report([old_finding]),
                current,
                per_provider=1,
            )
            review_repositories = []
            for repository in manifest["repositories"]:
                legacy_finding = json.loads(json.dumps(old_finding))
                repository_id = repository["id"]
                legacy_finding["span"]["file"] = (
                    repository_id + "/" + legacy_finding["span"]["file"]
                )
                legacy_finding["trace"][0]["span"]["file"] = (
                    repository_id + "/" + legacy_finding["trace"][0]["span"]["file"]
                )
                report_path = current / "reports" / repository["report"]
                report_path.write_text(
                    json.dumps(legacy_report([legacy_finding])),
                    encoding="utf-8",
                )
                review_repositories.append(
                    {
                        "diagnostics": [
                            {
                                "classification": "expected",
                                "id": old_finding["id"],
                                "reason": (
                                    "The immutable fixture retains the same reviewed "
                                    "supply-chain diagnostic semantics."
                                ),
                                "rule_id": old_finding["rule_id"],
                            }
                        ],
                        "id": repository_id,
                    }
                )
            old_review = current / "review-v1.json"
            old_review.write_text(
                json.dumps(
                    {
                        "repositories": review_repositories,
                        "schema": "corpus-review-v1",
                    }
                ),
                encoding="utf-8",
            )

            refreshed_path = root / "evaluation-refreshed"
            refresh(
                current,
                lambda _checkout: report([new_finding]),
                refreshed_path,
                workers=2,
            )
            rebased_path = refreshed_path / "review-v1.json"
            rebased = rebase_review(
                current / "corpus-v1.json",
                current / "reports",
                old_review,
                refreshed_path / "corpus-v1.json",
                refreshed_path / "reports",
                rebased_path,
            )
            self.assertTrue(
                all(
                    item["diagnostics"][0]["id"] == new_finding["id"]
                    for item in rebased["repositories"]
                )
            )
            apply_review(
                refreshed_path / "corpus-v1.json",
                refreshed_path / "reports",
                rebased_path,
            )

            first = manifest["repositories"][0]
            changed_report_path = refreshed_path / "reports" / first["report"]
            changed_report = json.loads(changed_report_path.read_text(encoding="utf-8"))
            changed_report["diagnostics"][0]["message"] = "changed semantic finding"
            changed_report_path.write_text(
                json.dumps(seal(changed_report)),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "diagnostic semantics changed"):
                rebase_review(
                    current / "corpus-v1.json",
                    current / "reports",
                    old_review,
                    refreshed_path / "corpus-v1.json",
                    refreshed_path / "reports",
                    root / "must-not-exist.json",
                )

    def test_refresh_rejects_tampered_source_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "evaluation"
            acquire(FakeSource(), lambda _checkout: report([]), current, per_provider=1)
            workflow = (
                current
                / "corpus"
                / "github"
                / "acme"
                / "github-project"
                / ".github"
                / "workflows"
                / "ci.yml"
            )
            workflow.write_text("tampered: true\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source digest"):
                refresh(
                    current,
                    lambda _checkout: report([]),
                    root / "evaluation-refreshed",
                )


if __name__ == "__main__":
    unittest.main()
