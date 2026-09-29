"""The release preconditions of docs/maintainers/PUBLISHING.md, checked on every push instead of at the last minute."""

import json
import os
import re
import tomllib
import unittest

from mcp_ssh_gateway import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
        return handle.read()


class TestTheVersionIsTheSameEverywhere(unittest.TestCase):
    def test_server_json_carries_the_version_of_the_code(self):
        document = json.loads(read("server.json"))
        self.assertEqual(document["version"], __version__)
        self.assertEqual([package["version"] for package in document["packages"]], [__version__])

    def test_the_changelog_has_a_section_for_it(self):
        self.assertRegex(read("CHANGELOG.md"), rf"(?m)^## \[{re.escape(__version__)}\]")

    def test_pyproject_reads_the_version_from_the_code_instead_of_repeating_it(self):
        pyproject = read("pyproject.toml")
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = { attr = "mcp_ssh_gateway.__version__" }', pyproject)


class TestThePackageMetadata(unittest.TestCase):
    def test_the_licence_is_an_spdx_expression_and_not_the_form_that_setuptools_retires_in_2027(self):
        project = tomllib.loads(read("pyproject.toml"))["project"]
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertEqual([tag for tag in project["classifiers"] if tag.startswith("License ::")], [])


class TestTheRegistryCanFindTheProject(unittest.TestCase):
    def test_the_readme_starts_with_the_ownership_line_of_the_registry_name(self):
        name = json.loads(read("server.json"))["name"]
        self.assertTrue(read("README.md").startswith(f"<!-- mcp-name: {name} -->\n"))

    def test_the_description_fits_what_the_registry_accepts(self):
        # the registry copies it into its metadata and refuses more than 100 characters (see PUBLISHING.md)
        self.assertLessEqual(len(json.loads(read("server.json"))["description"]), 100)


if __name__ == "__main__":
    unittest.main()
