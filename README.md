# DefectDojo MCP Server

The official open-source [Model Context Protocol](https://modelcontextprotocol.io) server for [DefectDojo](https://github.com/DefectDojo/django-DefectDojo).

It lets Claude, Cursor, VS Code and other MCP clients work with your DefectDojo instance through the DefectDojo REST API v2. Ask an assistant to find the open critical findings in a product, explain a finding, compare two imports, or (when you turn writes on) import a scan and update finding status.

- Works with open-source DefectDojo 2.x and 3.x, and with DefectDojo Pro.
- Read-only by default. Write tools only exist when you enable them.
- Text from DefectDojo is marked as untrusted, because scanner output can carry prompt injection.
- Runs locally over stdio, or as a streamable HTTP server with authentication.
- No telemetry of any kind.

<!-- mcp-name: io.github.DefectDojo/defectdojo-mcp -->

## Quick start

You need:

1. [uv](https://docs.astral.sh/uv/getting-started/installation/), which provides the `uvx` command.
2. The URL of your DefectDojo instance.
3. A DefectDojo API v2 key. In DefectDojo, open the user menu and choose **API v2 Key**. Use a dedicated account with only the permissions the assistant needs (see [Security](#security)).

Check that it starts:

```sh
DEFECTDOJO_URL=https://defectdojo.example.com DEFECTDOJO_API_KEY=your-key uvx defectdojo-mcp --help
```

Until the first release is on PyPI, run it from GitHub instead by replacing `uvx defectdojo-mcp` with `uvx --from git+https://github.com/DefectDojo/defectdojo-mcp defectdojo-mcp`.

### Claude Desktop

Open **Settings > Developer > Edit Config** and add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "defectdojo": {
      "command": "uvx",
      "args": ["defectdojo-mcp"],
      "env": {
        "DEFECTDOJO_URL": "https://defectdojo.example.com",
        "DEFECTDOJO_API_KEY": "your-api-key"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

### Claude Code

```sh
claude mcp add defectdojo \
  --env DEFECTDOJO_URL=https://defectdojo.example.com \
  --env DEFECTDOJO_API_KEY=your-api-key \
  -- uvx defectdojo-mcp
```

### Cursor

Add this to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "defectdojo": {
      "command": "uvx",
      "args": ["defectdojo-mcp"],
      "env": {
        "DEFECTDOJO_URL": "https://defectdojo.example.com",
        "DEFECTDOJO_API_KEY": "your-api-key"
      }
    }
  }
}
```

### VS Code

Add this to `.vscode/mcp.json`. VS Code asks for the API key once and stores it securely, so the key stays out of the file:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "defectdojo-api-key",
      "description": "DefectDojo API v2 key",
      "password": true
    }
  ],
  "servers": {
    "defectdojo": {
      "type": "stdio",
      "command": "uvx",
      "args": ["defectdojo-mcp"],
      "env": {
        "DEFECTDOJO_URL": "https://defectdojo.example.com",
        "DEFECTDOJO_API_KEY": "${input:defectdojo-api-key}"
      }
    }
  }
}
```

### Docker

```sh
docker build -t defectdojo-mcp .
docker run -i --rm \
  -e DEFECTDOJO_URL=https://defectdojo.example.com \
  -e DEFECTDOJO_API_KEY=your-api-key \
  defectdojo-mcp
```

Use `"command": "docker"` with these arguments in any client config above to run it in a container. For HTTP mode inside a container, bind all interfaces in the container (`--host 0.0.0.0`), publish the port to loopback only (`-p 127.0.0.1:8000:8000`), and set `DEFECTDOJO_MCP_ALLOWED_HOSTS`.

## Configuration

All settings come from environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `DEFECTDOJO_URL` | required | Base URL of the instance, for example `https://defectdojo.example.com`. A trailing `/api/v2` is accepted and removed. |
| `DEFECTDOJO_API_KEY` | required | API v2 key. Not needed in HTTP pass-through mode. Never logged. |
| `DEFECTDOJO_VERIFY_SSL` | `true` | `true`, `false`, or the path to a CA bundle for private certificate authorities. |
| `DEFECTDOJO_TIMEOUT` | `30` | Request timeout in seconds. |
| `DEFECTDOJO_ALLOW_WRITES` | `false` | Set to `true` to register the write tools. |
| `DEFECTDOJO_IMPORT_DIRS` | none | Folders that `import_scan` and `reimport_scan` may read report files from. Separate several with `:` (`;` on Windows). While unset, imports by file path are refused and only base64 uploads work. The home folder itself and the filesystem root are never accepted. |
| `DEFECTDOJO_MAX_UPLOAD_MB` | `25` | Largest scan report the server will upload. |
| `DEFECTDOJO_MCP_AUTH_TOKEN` | none | Bearer token that HTTP clients must send in token mode. |
| `DEFECTDOJO_MCP_ALLOWED_HOSTS` | none | Comma-separated host names accepted in the `Host` header when serving HTTP on a non-loopback address. |

## Tools

Every tool returns JSON. List tools are paged with `limit` and `offset`, and each page reports `count` and `next_offset`.

### Read tools (always available)

| Tool | What it does |
| --- | --- |
| `get_instance_info` | Instance URL, DefectDojo version, edition (open source or Pro, best effort), current user, and whether writes are on. |
| `list_findings` | Search findings by product, engagement, test, product type, severity, active, verified, duplicate, false positive, risk accepted, mitigated, out of scope, CVE or other vulnerability id, CWE, title text, component, file path, tags and dates. Sortable. |
| `get_finding` | One finding with full text fields, vulnerability ids, CWE, file path, component, notes, affected endpoints or locations, and its test, engagement and product. |
| `get_finding_stats` | Exact counts by severity and by status for a product, engagement, test, product type or the whole instance. |
| `list_finding_notes` | Notes on a finding. |
| `list_products`, `get_product` | Products. Newer releases call them assets. |
| `list_product_types` | Product types. Newer releases call them organizations. |
| `list_engagements`, `get_engagement` | Engagements. |
| `list_tests`, `get_test` | Tests, meaning individual scan imports or manual tests. |
| `list_scan_types` | Scan types the instance can import, for use as `scan_type`. |
| `list_test_imports` | Import and reimport history for a test, with the findings each run created, closed, reactivated or left untouched. |
| `get_current_user` | The user the API key belongs to. |
| `list_locations` | Hosts, URLs and other locations. Uses the locations API on newer releases and the endpoints API on older ones. |

### Write tools (only with `DEFECTDOJO_ALLOW_WRITES=true`)

| Tool | What it does |
| --- | --- |
| `import_scan` | Upload a scan report as a new test. Target an engagement id, or name a product and engagement and let DefectDojo create them with `auto_create_context`. Supports `close_old_findings`, `minimum_severity`, tags, scan date, version and CI metadata. |
| `reimport_scan` | Upload a newer report into an existing test so DefectDojo closes fixed findings and adds new ones. |
| `add_finding_note` | Add a note to a finding. |
| `update_finding_status` | Set active, verified, false positive, out of scope, or mitigated (with an optional date and note). |
| `risk_accept_findings` | Risk accept, or revoke acceptance for, up to 50 findings with DefectDojo's simple risk acceptance. |
| `create_product` | Create a product in a product type. |
| `create_engagement` | Create an engagement in a product. |

Scan reports reach the server in one of two ways. Over stdio, pass `file_path` pointing at a file inside one of the `DEFECTDOJO_IMPORT_DIRS` folders. Over stdio or HTTP, pass the report as `file_content_base64` with a `file_name`.

File path imports fail closed. With no `DEFECTDOJO_IMPORT_DIRS` set, the server refuses them instead of falling back to its working directory. It also refuses the home folder and the filesystem root as import folders, resolves symlinks before checking that a file is inside an allowed folder, rejects hidden files and anything inside a hidden folder (any path part that starts with a dot, before or after following symlinks), enforces the size limit, and never includes file contents in error messages. Point `DEFECTDOJO_IMPORT_DIRS` at a dedicated reports folder, not at a home folder or a whole repository.

### Prompts

| Prompt | What it does |
| --- | --- |
| `triage_critical_findings` | Walks through the open critical and high findings of a product and suggests a verdict for each. |
| `summarize_import_changes` | Summarizes what the latest import of a test created, closed and reactivated. |

## Read-only by default

Without `DEFECTDOJO_ALLOW_WRITES=true` the write tools are not registered at all, so an assistant cannot call them even by mistake. The prompts and server instructions also tell the assistant whether changes are possible.

To enable writes, add `"DEFECTDOJO_ALLOW_WRITES": "true"` to the `env` block of your client config. Most clients still ask you to approve each tool call, and the write tools carry MCP annotations that mark them as state-changing.

## Security

### Prompt injection

Finding titles, descriptions, notes, file paths, component names and similar fields usually come straight from scanner output. Anyone who controls something that gets scanned can put text there, including instructions aimed at an AI assistant.

This server wraps every free-text value from DefectDojo in a pair of tags with a random 16-character hex suffix chosen for that value, for example `<untrusted-data-3f9c0a7b1e2d4c58>...</untrusted-data-3f9c0a7b1e2d4c58>`. A client or model recognizes the data by the matching suffix on the opening and closing tag. Text inside cannot close the wrapper early because it cannot guess the suffix. As a second layer, look-alike tags inside the text are escaped, bidirectional control characters are shown as code points such as `[U+202E]`, and long fields are truncated. Tool descriptions and the server instructions tell the model to treat tagged text as data only. This lowers the risk but cannot remove it, so keep a person in the loop for write actions and review what the assistant proposes.

### Local files

A prompt-injected assistant could try to upload local files, such as keys or dotfiles, to DefectDojo through `import_scan`. That is why file path imports are off until you name the folders in `DEFECTDOJO_IMPORT_DIRS`, and why hidden files are always refused. Keep scan reports in their own folder.

### API key scope

The server can do anything the API key's user can do. Create a dedicated DefectDojo user for the assistant, give it access only to the products it needs, and keep writes off unless you need them. The key is sent only to `DEFECTDOJO_URL`, redirects are never followed, and the key is redacted from logs and error messages.

### HTTP mode

Over stdio the server is only reachable by the client that started it. HTTP mode is for shared or remote setups:

```sh
export DEFECTDOJO_URL=https://defectdojo.example.com
export DEFECTDOJO_API_KEY=your-api-key
export DEFECTDOJO_MCP_AUTH_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
defectdojo-mcp --transport http --host 127.0.0.1 --port 8000
```

The endpoint is `http://127.0.0.1:8000/mcp`, and `/healthz` answers without authentication for health checks. The server refuses to start in HTTP mode without one of these authentication modes:

- **Token mode** (`--http-auth token`, the default). Every request must send `Authorization: Bearer <DEFECTDOJO_MCP_AUTH_TOKEN>`. All callers share the server's DefectDojo key, so give that key the narrowest permissions that work for everyone.
- **Pass-through mode** (`--http-auth passthrough`). Every request carries the caller's own DefectDojo key in `X-DefectDojo-Api-Key` or `Authorization: Token <key>`. The server holds no key of its own and DefectDojo enforces each caller's permissions.

The server binds to `127.0.0.1` by default and checks the `Host` and `Origin` headers to block DNS rebinding. To serve other machines, bind a non-loopback address, set `DEFECTDOJO_MCP_ALLOWED_HOSTS` to the public host name, and put a TLS-terminating reverse proxy in front. Keys and tokens travel in headers, so plain HTTP across a network exposes them.

Report security problems as described in [SECURITY.md](SECURITY.md).

## Compatibility

- **Open-source DefectDojo 2.x and 3.x.** The server uses long-standing API v2 endpoints and skips fields a version does not return. On older releases, filters that the instance does not know are ignored by DefectDojo, so the date filters on `list_findings` need a release from late 2024 or newer. `list_locations` uses the locations API in 3.x and falls back to endpoints on older releases.
- **DefectDojo Pro.** Everything here works against Pro through the same API. Pro also includes its own built-in MCP server at `https://<your-instance>/mcp` with more capabilities, and `get_instance_info` mentions it when it detects Pro.
- **MCP.** Built on the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) 2.x and protocol version 2026-07-28, with fallback to earlier protocol versions for older clients.
- **Python** 3.11 or newer.

## Development

```sh
git clone https://github.com/DefectDojo/defectdojo-mcp
cd defectdojo-mcp
uv sync
uv run pytest            # unit tests with mocked HTTP
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

The live test suite runs every tool against a real DefectDojo instance over stdio. Point it at a disposable instance, since it creates products, engagements and findings:

```sh
DEFECTDOJO_LIVE_URL=http://127.0.0.1:8080 DEFECTDOJO_LIVE_API_KEY=your-key uv run pytest -m live
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
