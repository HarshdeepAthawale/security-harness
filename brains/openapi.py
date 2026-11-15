"""Turn an OpenAPI 3 / Swagger 2 spec into raw endpoint records for recon.

    from brains.openapi import endpoints_from_openapi
    raw = endpoints_from_openapi("crapi-openapi-spec.json")
    # [{"method": "GET", "path": "/workshop/api/shop/orders/{order_id}",
    #   "path_params": ["order_id"], "query_params": [], "auth_required": True}, ...]

The output is what recon.build_recon_map() takes, so the endpoint list no
longer has to be typed in by hand. Deterministic and offline: it reads a spec,
sends nothing, and uses no model.

Discovery only says what exists. What actually gets tested is decided later
by the signed contract (which methods, which paths) and by which objects the
run has ids for. brains/coverage.py reports the difference.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head")


def load_spec(source: dict | str | Path) -> dict:
    """A spec dict, or a path to a .json / .yaml / .yml file."""
    if isinstance(source, dict):
        return source
    path = Path(source)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "This spec is YAML: install PyYAML (pip install pyyaml) or convert it to JSON."
            ) from exc
        spec = yaml.safe_load(text)
    else:
        spec = json.loads(text)
    if not isinstance(spec, dict) or not ("paths" in spec):
        raise ValueError(f"{path} is not an OpenAPI/Swagger document (no 'paths')")
    return spec


def _resolve(spec: dict, item) -> dict:
    """Follow a local $ref like '#/components/parameters/OrderId'. External
    refs are not followed (they would mean reading arbitrary files or URLs)."""
    seen = 0
    while isinstance(item, dict) and "$ref" in item and seen < 10:
        ref = item["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        node = spec
        for part in ref[2:].split("/"):
            node = node.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(node, dict) else {}
        item, seen = node, seen + 1
    return item if isinstance(item, dict) else {}


def _base_path(spec: dict) -> str:
    """Path prefix from OAS3 servers[0].url or Swagger 2 basePath."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", ""))
        path = urlparse(url).path if "://" in url else url
    else:
        path = str(spec.get("basePath", ""))
    path = path.rstrip("/")
    return path if path.startswith("/") or not path else "/" + path


def endpoints_from_openapi(source: dict | str | Path, base_path: str | None = None) -> list[dict]:
    """Every operation in the spec as
    {method, path, path_params, query_params, auth_required}.

    base_path overrides the prefix taken from servers / basePath (pass "" to
    use the spec's paths exactly as written).
    """
    spec = load_spec(source)
    prefix = _base_path(spec) if base_path is None else base_path.rstrip("/")
    global_security = spec.get("security") or []
    endpoints = []
    for raw_path, path_item in (spec.get("paths") or {}).items():
        path_item = _resolve(spec, path_item)
        shared = [_resolve(spec, p) for p in path_item.get("parameters", [])]
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            params = shared + [_resolve(spec, p) for p in op.get("parameters", [])]
            by_location = {"path": [], "query": []}
            for param in params:
                if param.get("in") in by_location and param.get("name"):
                    by_location[param["in"]].append(param["name"])
            # Operation-level security overrides the global one; [] means "no auth".
            security = op["security"] if "security" in op else global_security
            endpoints.append({
                "method": method.upper(),
                "path": prefix + "/" + raw_path.lstrip("/"),
                "path_params": list(dict.fromkeys(by_location["path"])),
                "query_params": list(dict.fromkeys(by_location["query"])),
                "auth_required": bool(security),
            })
    return endpoints
