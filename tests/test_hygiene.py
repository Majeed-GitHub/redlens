"""Repository hygiene: things that are not tests of behaviour but must stay true."""

import pathlib
import re
import unittest
import warnings

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestNoInvalidEscapes(unittest.TestCase):
    def test_every_module_compiles_without_a_syntax_warning(self):
        """A non-raw string containing a regex escape warns on 3.12 and fails later.

        A stranger cloning the repository saw this warning before they saw a test
        result, which is the wrong first impression for a security tool.
        """
        problems = []
        for path in sorted(ROOT.rglob("*.py")):
            if any(part in (".git", "_scratch", "build", "dist") for part in path.parts):
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", SyntaxWarning)
                try:
                    compile(source, str(path), "exec")
                except SyntaxError as error:
                    problems.append("%s: %s" % (path.relative_to(ROOT), error))
                    continue
                for warning in caught:
                    if issubclass(warning.category, SyntaxWarning):
                        problems.append("%s: %s" % (path.relative_to(ROOT), warning.message))
        self.assertEqual(problems, [])


class TestVersionIsHonest(unittest.TestCase):
    """The package, the project metadata and the changelog must agree.

    v0.8.3 and v0.8.4 were tagged and released while __init__.py still said
    0.8.2, so 'redlens --version' and every SARIF log from those releases
    carried the wrong version. A test is the only thing that catches it: no
    reviewer reads two files to compare version strings.
    """

    def test_pyproject_version_matches_the_package(self):
        from redlens import __version__

        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
        self.assertIsNotNone(match, "pyproject.toml has no version line")
        self.assertEqual(match.group(1), __version__)

    def test_changelog_documents_the_current_version(self):
        from redlens import __version__

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## " + __version__, changelog,
                      "CHANGELOG.md has no entry for " + __version__)

    def test_version_looks_like_semver(self):
        from redlens import __version__

        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
