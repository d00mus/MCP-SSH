"""The README is what an agent's owner reads first; it must not promise what the code does not do."""

import glob
import json
import os
import re
import unittest

from mcp_ssh_gateway.main import build_parser
from mcp_ssh_gateway.server import ADD_SERVER_TOOL, TOOLS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
READMES = ("README.md", "README.ru.md")


def read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
        return handle.read()


def fenced_blocks(text: str, language: str) -> "list[str]":
    return re.findall(rf"(?ms)^```{language}\n(.*?)^```", text)


class TestTheExamplesAreValid(unittest.TestCase):
    def test_every_json_example_parses(self):
        for name in READMES:
            blocks = fenced_blocks(read(name), "json")
            self.assertTrue(blocks, f"{name} has no JSON example")
            for block in blocks:
                with self.subTest(readme=name, example=block.strip()[:40]):
                    json.loads(block)

    def test_the_transcript_calls_only_tools_and_arguments_that_exist(self):
        arguments_of = {tool["name"]: set(tool["inputSchema"]["properties"]) for tool in [*TOOLS, ADD_SERVER_TOOL]}
        for name in READMES:
            transcript = "\n".join(fenced_blocks(read(name), "text"))
            calls = re.findall(r"(?m)^(\w+)\((.*?)\)\s*(?:#.*)?$", transcript)
            self.assertTrue(calls, f"{name} has no transcript")
            for tool, arguments in calls:
                with self.subTest(readme=name, call=f"{tool}({arguments})"):
                    self.assertIn(tool, arguments_of)
                    written = re.sub(r'"[^"]*"', '""', arguments)  # the values may contain anything
                    self.assertLessEqual(set(re.findall(r"(\w+)=", written)), arguments_of[tool])


class TestTheOptionsAreDocumented(unittest.TestCase):
    def test_the_options_table_lists_exactly_the_options_of_the_program(self):
        options = set(re.findall(r"--[a-z][a-z-]*", build_parser().format_help())) - {"--help", "--version"}
        for name in READMES:
            first_cells = re.findall(r"(?m)^\|([^|\n]*)\|", read(name))
            documented = {flag for cell in first_cells for flag in re.findall(r"--[a-z][a-z-]*", cell)}
            with self.subTest(readme=name):
                self.assertEqual(documented, options)


class TestTheDocumentsFindEachOther(unittest.TestCase):
    def test_the_two_readmes_link_to_each_other(self):
        self.assertTrue("README.ru.md" in read("README.md"), "README.md does not link to README.ru.md")
        self.assertTrue("README.md" in read("README.ru.md"), "README.ru.md does not link to README.md")

    def test_relative_links_point_at_files_that_exist(self):
        documents = [os.path.join(ROOT, name) for name in ("README.md", "README.ru.md", "CONTRIBUTING.md",
                                                           "SECURITY.md", "CHANGELOG.md")]
        documents += glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        for document in documents:
            with open(document, encoding="utf-8") as handle:
                targets = re.findall(r"\]\(([^)\s]+)\)", handle.read())
            for target in targets:
                if re.match(r"(?:[a-z]+:|#)", target):
                    continue
                path = os.path.join(os.path.dirname(document), target.split("#")[0])
                with self.subTest(document=os.path.relpath(document, ROOT), link=target):
                    self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
