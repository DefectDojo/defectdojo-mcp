"""Turn DefectDojo API objects into compact, model-friendly dictionaries.

Every free-text value is wrapped as untrusted data. Only numbers, booleans,
dates and timestamps, and a few server-side enum choices pass through
unwrapped, and even those are type-checked: anything that does not look like
the expected structured value gets wrapped too. Unknown or missing fields are
skipped so the same code works across DefectDojo versions.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlunsplit

from defectdojo_mcp.untrusted import wrap, wrap_list, wrap_short

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})?)?$")
_ENUM_RE = re.compile(r"^[A-Za-z0-9 ,/_.-]{1,40}$")

# Keys whose string values are server-side choices (severity, status and similar).
ENUM_KEYS = frozenset(
    {
        "severity",
        "numerical_severity",
        "minimum_severity",
        "status",
        "business_criticality",
        "lifecycle",
        "platform",
        "origin",
        "engagement_type",
        "type",
    }
)


def _safe(key: str, value: Any) -> Any:
    """Return value unchanged if it is structured data, otherwise wrap it."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if _DATE_RE.match(value) or (key in ENUM_KEYS and _ENUM_RE.match(value)):
            return value
        return wrap_short(value)
    if isinstance(value, list):
        return [_safe(key, v) for v in value[:100]]
    if isinstance(value, dict):
        return {str(k)[:40] if _ENUM_RE.match(str(k)) else wrap_short(k): _safe(str(k), v) for k, v in value.items()}
    return wrap_short(value)


def safe_value(key: str, value: Any) -> Any:
    """Public form of _safe for values shaped outside this module."""
    return _safe(key, value)


def _pick(record: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: _safe(k, record[k]) for k in keys if k in record and record[k] is not None}


def _short(record: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: wrap_short(record[k]) for k in keys if record.get(k) not in (None, "")}


def _long(record: dict[str, Any], keys: tuple[str, ...], max_chars: int) -> dict[str, Any]:
    return {k: wrap(record[k], max_chars) for k in keys if record.get(k) not in (None, "")}


def _vulnerability_ids(record: dict[str, Any]) -> list[str]:
    raw = record.get("vulnerability_ids") or []
    values: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            value = item.get("vulnerability_id")
            if value:
                values.append(str(value))
        elif item:
            values.append(str(item))
    if not values and record.get("cve"):
        values.append(str(record["cve"]))
    return wrap_list(values)


def finding_status(record: dict[str, Any]) -> str:
    """Human-readable status, using display_status when the server provides it."""
    if record.get("display_status"):
        return str(record["display_status"])
    parts: list[str] = []
    if record.get("active"):
        parts.append("Active")
    else:
        parts.append("Inactive")
    for key, label in (
        ("verified", "Verified"),
        ("is_mitigated", "Mitigated"),
        ("false_p", "False Positive"),
        ("out_of_scope", "Out Of Scope"),
        ("duplicate", "Duplicate"),
        ("risk_accepted", "Risk Accepted"),
    ):
        if record.get(key):
            parts.append(label)
    return ", ".join(parts)


FINDING_SUMMARY_KEYS = (
    "id",
    "severity",
    "active",
    "verified",
    "false_p",
    "duplicate",
    "out_of_scope",
    "risk_accepted",
    "is_mitigated",
    "date",
    "mitigated",
    "cwe",
    "test",
    "line",
    "epss_score",
    "epss_percentile",
    "known_exploited",
    "fix_available",
    "sla_expiration_date",
    "sla_days_remaining",
    "created",
    "last_status_update",
)


def finding_summary(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(record, FINDING_SUMMARY_KEYS)
    out["status"] = _safe("status", finding_status(record))
    out.update(_short(record, ("title", "component_name", "component_version", "file_path")))
    vulns = _vulnerability_ids(record)
    if vulns:
        out["vulnerability_ids"] = vulns
    tags = wrap_list(record.get("tags"))
    if tags:
        out["tags"] = tags
    return out


FINDING_DETAIL_EXTRA_KEYS = (
    "numerical_severity",
    "cvssv3_score",
    "cvssv4_score",
    "nb_occurences",
    "static_finding",
    "dynamic_finding",
    "under_review",
    "planned_remediation_date",
    "kev_date",
    "ransomware_used",
    "publish_date",
    "updated",
    "found_by",
    "reporter",
    "mitigated_by",
    "duplicate_finding",
    "sast_source_line",
)

FINDING_LONG_TEXT = (
    "description",
    "mitigation",
    "impact",
    "steps_to_reproduce",
    "severity_justification",
    "references",
)

FINDING_SHORT_TEXT = (
    "cvssv3",
    "cvssv4",
    "unique_id_from_tool",
    "vuln_id_from_tool",
    "service",
    "param",
    "payload",
    "sast_source_object",
    "sast_sink_object",
    "sast_source_file_path",
    "fix_version",
    "planned_remediation_version",
    "effort_for_fixing",
    "test_type_name",
)


def finding_detail(record: dict[str, Any], max_chars: int) -> dict[str, Any]:
    out = finding_summary(record)
    out.update(_pick(record, FINDING_DETAIL_EXTRA_KEYS))
    out.update(_short(record, FINDING_SHORT_TEXT))
    out.update(_long(record, FINDING_LONG_TEXT, max_chars))
    cwes = record.get("cwes")
    if isinstance(cwes, list) and cwes:
        out["cwes"] = wrap_list(c.get("cwe") if isinstance(c, dict) else c for c in cwes)
    return out


def note(record: dict[str, Any], max_chars: int) -> dict[str, Any]:
    out = _pick(record, ("id", "date", "private", "edited", "edit_time"))
    author = record.get("author")
    if isinstance(author, dict):
        out["author"] = wrap_short(author.get("username"))
    note_type = record.get("note_type")
    if isinstance(note_type, dict) and note_type.get("name"):
        out["note_type"] = wrap_short(note_type["name"])
    out["entry"] = wrap(record.get("entry"), max_chars)
    return out


def _endpoint_to_url(record: dict[str, Any]) -> str | None:
    host = record.get("host")
    if not host:
        return None
    netloc = str(host)
    if record.get("port"):
        netloc = f"{netloc}:{record['port']}"
    path = str(record.get("path") or "")
    if path and not path.startswith("/"):
        path = "/" + path
    return urlunsplit((str(record.get("protocol") or ""), netloc, path, str(record.get("query") or ""), ""))


def location(record: dict[str, Any]) -> dict[str, Any]:
    """Shape either a legacy Endpoint or a newer Location / location reference."""
    out = _pick(record, ("id", "status", "product", "location", "finding", "active_finding_count"))
    out.update(_short(record, ("location_type",)))
    if "location_value" in record:
        out["value"] = wrap_short(record.get("location_value"))
    else:
        out["value"] = wrap_short(_endpoint_to_url(record) or record.get("host"))
    tags = wrap_list(record.get("tags"))
    if tags:
        out["tags"] = tags
    return out


def product(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(
        record,
        (
            "id",
            "prod_type",
            "findings_count",
            "business_criticality",
            "lifecycle",
            "platform",
            "origin",
            "internet_accessible",
            "external_audience",
            "enable_simple_risk_acceptance",
            "enable_full_risk_acceptance",
            "created",
            "updated",
        ),
    )
    out.update(_short(record, ("name",)))
    out.update(_long(record, ("description",), 1000))
    tags = wrap_list(record.get("tags"))
    if tags:
        out["tags"] = tags
    return out


def product_type(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(record, ("id", "critical_product", "key_product", "created", "updated"))
    out.update(_short(record, ("name",)))
    out.update(_long(record, ("description",), 1000))
    return out


def engagement(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(
        record,
        (
            "id",
            "product",
            "status",
            "engagement_type",
            "active",
            "target_start",
            "target_end",
            "lead",
            "created",
            "updated",
            "deduplication_on_engagement",
        ),
    )
    out.update(_short(record, ("name", "version", "branch_tag", "commit_hash", "build_id")))
    out.update(_long(record, ("description",), 1000))
    tags = wrap_list(record.get("tags"))
    if tags:
        out["tags"] = tags
    return out


def test_record(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(
        record,
        (
            "id",
            "engagement",
            "test_type",
            "target_start",
            "target_end",
            "percent_complete",
            "lead",
            "created",
            "updated",
        ),
    )
    out.update(
        _short(record, ("title", "test_type_name", "scan_type", "version", "branch_tag", "commit_hash", "build_id"))
    )
    out.update(_long(record, ("description",), 1000))
    tags = wrap_list(record.get("tags"))
    if tags:
        out["tags"] = tags
    return out


ACTION_LABELS = {"N": "created", "C": "closed", "R": "reactivated", "U": "left_untouched"}


def import_history(record: dict[str, Any], max_ids: int = 100) -> dict[str, Any]:
    out = _pick(record, ("id", "test", "type", "created", "modified"))
    out.update(_short(record, ("version", "branch_tag", "commit_hash", "build_id")))
    actions = record.get("test_import_finding_action_set") or []
    grouped: dict[str, list[int]] = {}
    for action in actions:
        if not isinstance(action, dict):
            continue
        code = str(action.get("action"))
        label = ACTION_LABELS.get(code) or wrap_short(code) or "unknown"
        finding_id = action.get("finding")
        if isinstance(finding_id, int) and not isinstance(finding_id, bool):
            grouped.setdefault(label, []).append(finding_id)
    out["finding_counts"] = {label: len(ids) for label, ids in grouped.items()}
    out["finding_ids"] = {label: sorted(ids)[:max_ids] for label, ids in grouped.items()}
    settings = record.get("import_settings")
    if isinstance(settings, dict):
        out["import_settings"] = {
            k: _safe(k, settings[k])
            for k in ("close_old_findings", "minimum_severity", "active", "verified", "scan_date", "do_not_reactivate")
            if k in settings
        }
    return out


def user(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(record, ("id", "is_active", "is_staff", "is_superuser", "date_joined", "last_login"))
    out.update(_short(record, ("username", "first_name", "last_name", "email")))
    return out


def import_result(record: dict[str, Any]) -> dict[str, Any]:
    out = _pick(
        record,
        (
            "test",
            "test_id",
            "engagement_id",
            "product_id",
            "product_type_id",
            "minimum_severity",
            "close_old_findings",
            "statistics",
        ),
    )
    out.update(_short(record, ("scan_type", "test_title", "product_name", "engagement_name", "product_type_name")))
    return out
