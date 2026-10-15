# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- First release of the open-source DefectDojo MCP server, built on the MCP Python SDK 2.x.
- Read tools: `get_instance_info`, `list_findings`, `get_finding`, `get_finding_stats`, `list_finding_notes`, `list_products`, `get_product`, `list_product_types`, `list_engagements`, `get_engagement`, `list_tests`, `get_test`, `list_scan_types`, `list_test_imports`, `get_current_user`, `list_locations`.
- Write tools, registered only when `DEFECTDOJO_ALLOW_WRITES=true`: `import_scan`, `reimport_scan`, `add_finding_note`, `update_finding_status`, `risk_accept_findings`, `create_product`, `create_engagement`.
- Prompts: `triage_critical_findings` and `summarize_import_changes`.
- stdio transport, plus streamable HTTP with bearer token or per-request DefectDojo key pass-through.
- Untrusted-content markers and truncation for all free text returned from DefectDojo.
- Best-effort DefectDojo Pro detection with a pointer to Pro's built-in MCP server.

[0.1.0]: https://github.com/DefectDojo/defectdojo-mcp/releases/tag/v0.1.0
