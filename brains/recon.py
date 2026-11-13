"""Clean raw endpoint records into a deterministic resource map."""
import re
from collections import defaultdict
from typing import Any
from .schemas import Endpoint

_PLACEHOLDER = re.compile(r"\{([^{}]+)\}|:([A-Za-z_][A-Za-z0-9_]*)|<([^<>]+)>")

def _path_params(path: str, supplied: Any) -> list[str]:
    """Find ID names written in the path and combine supplied names."""
    names = [m.group(1) or m.group(2) or m.group(3) for m in _PLACEHOLDER.finditer(path)]
    if isinstance(supplied, list):
        names.extend(str(item) for item in supplied if item)
    return list(dict.fromkeys(names))

def _resource_type(path: str) -> str:
    """Use the path segment immediately before an ID as its resource name."""
    parts = [part for part in path.strip("/").split("/") if part]
    for index, part in enumerate(parts):
        if _PLACEHOLDER.search(part) and index:
            return parts[index - 1].lower()
    return "unknown"

def build_recon_map(raw_endpoints: list[dict]) -> dict:
    """Keep endpoints with path IDs and group them by resource."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for raw in raw_endpoints:
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path", "")).strip()
        method = str(raw.get("method", "")).strip().upper()
        if not path.startswith("/") or not method:
            continue
        if not _PLACEHOLDER.search(path):
            continue
        params = _path_params(path, raw.get("path_params", []))
        if not params:
            continue
        endpoint = Endpoint(method, path, params, raw.get("auth_required") is True)
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        grouped[_resource_type(path)].append(endpoint.__dict__)
    return {"resources": [
        {"resource_type": name, "endpoints": sorted(items, key=lambda e: (e["path"], e["method"]))}
        for name, items in sorted(grouped.items())
    ]}
