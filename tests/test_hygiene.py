"""Repository hygiene: things that are not tests of behaviour but must stay true."""

import pathlib
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


if __name__ == "__main__":
    unittest.main()
