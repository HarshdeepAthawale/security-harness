"""Honest coverage: for every endpoint discovery found, was it tested, and if
not, why not. Activity is not coverage (PROJECT.md section 1): a run that
discovered 44 operations and tested 1 must say so.

Deterministic, offline, no model. The statuses:

  tested            read-only, one path id, and the run has an object id for it
  needs_object_ids  would be tested, but no object id was supplied for its resource type
  id_in_query       the object id is a query parameter; recon only handles path ids
  multiple_ids      more than one path id; per-id objects aren't supported yet
  not_read_only     a write method (POST/PUT/PATCH/DELETE); IDOR on writes is its own pack
  public            needs no authentication, so it isn't an access-control target
  no_object_id      no id in the path or query: nothing to swap between users
"""
from __future__ import annotations

import re

from .recon import _PLACEHOLDER, _resource_type

READ_METHODS = frozenset({"GET", "HEAD"})

# id, report_id, report-id, reportId, UUID ... but not "paid", "valid" or "android".
_ID_NAME = re.compile(r"(?i:(^|[_-])(id|uuid|guid)$)|[a-z](Id|ID|Uuid|UUID)$")

ORDER = ("tested", "needs_object_ids", "id_in_query", "multiple_ids", "not_read_only", "public", "no_object_id")


def _id_like_query(names) -> list[str]:
    return [n for n in names if _ID_NAME.search(n)]


def classify(endpoint: dict, object_ids: dict, allow_write: bool = False) -> tuple[str, str]:
    """(status, reason) for one discovered endpoint."""
    method = str(endpoint.get("method", "")).upper()
    path = str(endpoint.get("path", ""))
    path_params = list(endpoint.get("path_params") or [])
    if not path_params:
        path_params = [m.group(1) or m.group(2) or m.group(3) for m in _PLACEHOLDER.finditer(path)]

    if endpoint.get("auth_required") is not True:
        return "public", "needs no authentication"
    if method not in READ_METHODS and not allow_write:
        return "not_read_only", f"{method} changes data"
    if not path_params:
        query_ids = _id_like_query(endpoint.get("query_params") or [])
        if query_ids:
            return "id_in_query", f"object id is the query parameter {query_ids[0]!r}"
        return "no_object_id", "no id in the path or query"
    if len(path_params) > 1:
        return "multiple_ids", f"{len(path_params)} path ids: {', '.join(path_params)}"
    resource = _resource_type(path)
    if not object_ids.get(resource):
        return "needs_object_ids", f"no object ids supplied for resource {resource!r}"
    return "tested", f"resource {resource!r}, ids for {', '.join(sorted(object_ids[resource]))}"


def coverage_report(raw_endpoints: list[dict], object_ids: dict, allow_write: bool = False) -> dict:
    """{"total", "counts": {status: n}, "entries": [{method, path, status, reason}]}"""
    entries = []
    for endpoint in raw_endpoints:
        status, reason = classify(endpoint, object_ids, allow_write)
        entries.append({"method": str(endpoint.get("method", "")).upper(), "path": endpoint.get("path", ""),
                        "status": status, "reason": reason})
    counts = {status: sum(e["status"] == status for e in entries) for status in ORDER}
    return {"total": len(entries), "counts": {k: v for k, v in counts.items() if v}, "entries": entries}


def format_coverage(report: dict, show: tuple[str, ...] = ("tested", "needs_object_ids", "id_in_query", "multiple_ids")) -> str:
    """A short plain-text summary. Statuses in `show` are listed one per line;
    the rest are only counted."""
    counts = report["counts"]
    lines = [f"Coverage: {report['total']} operations discovered, {counts.get('tested', 0)} tested"]
    lines += [f"  {status:17s} {counts[status]}" for status in ORDER if status in counts]
    for status in show:
        for entry in report["entries"]:
            if entry["status"] == status:
                lines.append(f"  [{status}] {entry['method']} {entry['path']}  ({entry['reason']})")
    return "\n".join(lines)
