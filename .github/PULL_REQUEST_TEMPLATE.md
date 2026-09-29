## What changes for someone running this server

<!-- The user-visible effect, not the diff. -->

## The agent's view

<!-- Delete this section for changes that do not touch what the agent gets back. -->

- [ ] The shape of the answers is unchanged, or `tests/test_contract.py` was updated on purpose
- [ ] `has_more` still counts unread lines and `offset` never moves the unread position
- [ ] No prompt markers or setup commands reach the output
- [ ] A non-zero exit code is still a result (`status: completed`), not a tool error
- [ ] The tool catalogue did not grow, or the new tool is worth its tokens in every session

## Checks

- [ ] `python -m unittest discover -s tests -t .` passes (integration tests need Docker)
- [ ] `ruff check .` and `mypy` are clean
- [ ] Tests were added or updated (a bug fix starts with the test that fails)
- [ ] `CHANGELOG.md` is updated under `[Unreleased]`
