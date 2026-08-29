import unittest

from scripts.verify_pr_title import validate_title


class VerifyPullRequestTitleTests(unittest.TestCase):
    def test_valid_titles_cover_scopes_breaking_releases_and_dependabot(self) -> None:
        titles = [
            "feat: add policy explanation",
            "fix(parser): retain folded scalar span",
            "refactor(core)!: remove the legacy graph field",
            "docs!: replace a published compatibility promise",
            "chore: release v0.1.0",
            "deps(actions): bump the actions group",
            "deps(rust): bump the rust group",
            "style: apply canonical formatting",
        ]
        for title in titles:
            with self.subTest(title=title):
                self.assertEqual(validate_title(title), title)

    def test_invalid_titles_fail_closed(self) -> None:
        titles = [
            "Add policy explanation",
            "feature: add policy explanation",
            "feat(parser: missing parenthesis",
            "feat(): empty scope",
            "feat: ",
            "feat:  leading summary space",
            "feat: trailing summary space ",
            "feat: first line\nsecond line",
            "feat(parser) !: misplaced breaking marker",
        ]
        for title in titles:
            with self.subTest(title=title), self.assertRaises(ValueError):
                validate_title(title)


if __name__ == "__main__":
    unittest.main()
