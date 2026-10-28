# Contributing

Thanks for helping improve the DefectDojo MCP server. Bug reports, fixes, new tools and documentation improvements are all welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.11 or newer.

```sh
git clone https://github.com/DefectDojo/defectdojo-mcp
cd defectdojo-mcp
uv sync
```

## Checks

Pull requests must pass the same checks as CI:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Unit tests mock DefectDojo with [respx](https://lundberg.github.io/respx/), so they need no network. When you change how the server talks to DefectDojo, please also run the live suite against a disposable local instance:

```sh
git clone --depth 1 https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo && docker compose up -d
docker compose logs initializer | grep "Admin password:"
# create an API key for the admin user, then from this repository:
DEFECTDOJO_LIVE_URL=http://127.0.0.1:8080 DEFECTDOJO_LIVE_API_KEY=your-key uv run pytest -m live
```

## Guidelines for tools

- Check endpoint paths and field names against the DefectDojo OpenAPI schema at `/api/v2/oa3/schema/`.
- Keep new tools read-only unless they truly need to change data. Register write tools only in `tools/write.py`, which is skipped when writes are disabled.
- Wrap every free-text value that comes from DefectDojo with the helpers in `untrusted.py`, and mention the untrusted-data markers in the tool description.
- Validate inputs with type hints and `pydantic.Field` limits, cap page sizes, and turn API errors into clear messages.
- Never log or return API keys or tokens.
- Write descriptions and docs in plain language.

## Commits and pull requests

Keep pull requests focused, describe what changed and why, and add tests for new behavior. Add a line to `CHANGELOG.md` under the unreleased section.

By contributing you agree that your contributions are licensed under the project's [BSD 3-Clause license](LICENSE).

## Releases

Maintainers release by bumping the version in `pyproject.toml`, `server.json` (the top-level version, the PyPI package version and the image tag) and `CHANGELOG.md`, then pushing a `vX.Y.Z` tag. The release workflow fails if they disagree. The release workflow always builds the wheel, sdist and Docker image. Each publishing step stays off until its repository variable is set:

- `PUBLISH_PYPI=true` publishes `defectdojo-mcp-server` to PyPI with trusted publishing, from the `pypi` environment. Configure the trusted publisher on PyPI first: owner `DefectDojo`, repository `defectdojo-mcp`, workflow `release.yml`, environment `pypi`. The PyPI name `defectdojo-mcp` belongs to an unrelated project.
- `PUBLISH_IMAGE=true` pushes the image to `ghcr.io/defectdojo/defectdojo-mcp`, tagged with the bare version (`0.1.0`), the tag (`v0.1.0`) and `latest`. The package must be public for the MCP registry to read it.
- `PUBLISH_MCP_REGISTRY=true` publishes `server.json` to the official MCP registry as `io.github.DefectDojo/defectdojo-mcp`, after both the PyPI upload and the image push.
