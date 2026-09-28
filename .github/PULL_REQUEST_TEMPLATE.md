name: Pull request
description: A change to code, tests or documentation.
labels: ["change"]
body:
  - type: textarea
    id: summary
    attributes:
      label: User-visible effect
      description: What changes for someone running this server.
    validations:
      required: true
  - type: textarea
    id: contract
    attributes:
      label: Output contract
      description: Confirm none of these regress: `has_more` counts unread lines; `line_limit` counts lines; `offset` never consumes; no internal markers or prompts reach the agent; non-zero exit stays `completed_nonzero`; every tool keeps its annotations.
  - type: checkboxes
    id: checks
    attributes:
      label: Checks
      options:
        - label: python -m unittest discover -s tests -t . passes
        - label: Tests added or updated
        - label: CHANGELOG.md updated under [Unreleased]
