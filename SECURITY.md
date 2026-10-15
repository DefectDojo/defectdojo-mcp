# Security

No technology is perfect, and we value the work of security researchers who help keep DefectDojo and its users safe. If you believe you have found a security issue in this MCP server, please tell us.

## Reporting

Report it through the DefectDojo HackerOne [disclosure submission program](https://hackerone.com/defectdojo/reports/new). Please do not open a public GitHub issue for security problems.

After we assess the report, we create a private GitHub security advisory and invite you to collaborate on the fix. Fixes ship in the next release, which is marked as a security release. Details stay embargoed for 30 days so users can upgrade, and then we coordinate disclosure with you. If you contributed the fix, you will be credited.

The full policy, including safe harbor and exclusions, is in the main [DefectDojo security policy](https://github.com/DefectDojo/django-DefectDojo/blob/master/SECURITY.md).

## Scope notes

Prompt injection through finding text is a known limitation of any assistant that reads scanner output. This server marks such text as untrusted, but a model may still be influenced by it. Reports that show a way around the untrusted-data markers, a way to reach write tools while writes are disabled, a way to read files outside the allowed import folders, or a leak of API keys or tokens are all in scope and welcome.

## Supported versions

Security fixes go into the latest release.
