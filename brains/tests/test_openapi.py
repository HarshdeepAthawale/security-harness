"""Endpoint discovery: OpenAPI -> raw endpoints -> honest coverage."""
import json
from pathlib import Path

import pytest

from brains.adapter import IdorBrains
from brains.coverage import classify, coverage_report, format_coverage
from brains.openapi import endpoints_from_openapi, load_spec
from brains.recon import build_recon_map
from tests.fakes import make_contract

SPEC = {
    "openapi": "3.0.1",
    "servers": [{"url": "http://localhost:8888/api"}],
    "security": [{"bearerAuth": []}],
    "paths": {
        "/orders/{order_id}": {
            "parameters": [{"name": "order_id", "in": "path", "required": True}],        # path-level
            "get": {},
            "put": {},
            "delete": {},
        },
        "/users/{uid}/files/{fid}": {"get": {"parameters": [{"name": "uid", "in": "path"}, {"name": "fid", "in": "path"}]}},
        "/reports": {"get": {"parameters": [{"name": "report_id", "in": "query"}, {"name": "paid", "in": "query"}]}},
        "/health": {"get": {"security": []}},                                          # explicitly public
        "/refs/{rid}": {"get": {"parameters": [{"$ref": "#/components/parameters/Rid"}]}},
        "/external/{x}": {"get": {"parameters": [{"$ref": "http://evil.example/p.json"}]}},
    },
    "components": {"parameters": {"Rid": {"name": "rid", "in": "path"}}},
}


def by_key(endpoints):
    return {(e["method"], e["path"]): e for e in endpoints}


# -- the importer ----------------------------------------------------------------

def test_every_operation_is_found_with_the_servers_prefix():
    found = by_key(endpoints_from_openapi(SPEC))
    assert ("GET", "/api/orders/{order_id}") in found
    assert {m for m, p in found if p == "/api/orders/{order_id}"} == {"GET", "PUT", "DELETE"}


def test_path_level_parameters_and_refs_are_followed():
    found = by_key(endpoints_from_openapi(SPEC))
    assert found[("GET", "/api/orders/{order_id}")]["path_params"] == ["order_id"]
    assert found[("GET", "/api/refs/{rid}")]["path_params"] == ["rid"]


def test_external_refs_are_not_followed():
    assert by_key(endpoints_from_openapi(SPEC))[("GET", "/api/external/{x}")]["path_params"] == []


def test_security_is_inherited_and_can_be_switched_off_per_operation():
    found = by_key(endpoints_from_openapi(SPEC))
    assert found[("GET", "/api/orders/{order_id}")]["auth_required"] is True
    assert found[("GET", "/api/health")]["auth_required"] is False


def test_base_path_can_be_overridden():
    assert ("GET", "/orders/{order_id}") in by_key(endpoints_from_openapi(SPEC, base_path=""))


def test_swagger2_base_path():
    spec = {"swagger": "2.0", "basePath": "/v1", "paths": {"/a/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}}}}
    assert endpoints_from_openapi(spec)[0]["path"] == "/v1/a/{id}"


def test_query_parameters_are_recorded():
    assert by_key(endpoints_from_openapi(SPEC))[("GET", "/api/reports")]["query_params"] == ["report_id", "paid"]


def test_a_non_spec_file_is_refused(tmp_path):
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ValueError, match="not an OpenAPI"):
        load_spec(path)


def test_the_output_feeds_recon_unchanged():
    resources = build_recon_map(endpoints_from_openapi(SPEC))["resources"]
    assert "orders" in {r["resource_type"] for r in resources}


# -- coverage -------------------------------------------------------------------------

OBJECTS = {"orders": {"user_A": "1", "user_B": "2"}}


@pytest.mark.parametrize("endpoint, status", [
    ({"method": "GET", "path": "/api/orders/{order_id}", "path_params": ["order_id"], "auth_required": True}, "tested"),
    ({"method": "GET", "path": "/api/files/{fid}", "path_params": ["fid"], "auth_required": True}, "needs_object_ids"),
    ({"method": "PUT", "path": "/api/orders/{order_id}", "path_params": ["order_id"], "auth_required": True}, "not_read_only"),
    ({"method": "GET", "path": "/api/users/{u}/files/{f}", "path_params": ["u", "f"], "auth_required": True}, "multiple_ids"),
    ({"method": "GET", "path": "/api/reports", "query_params": ["report_id"], "auth_required": True}, "id_in_query"),
    ({"method": "GET", "path": "/api/reports", "query_params": ["paid", "valid"], "auth_required": True}, "no_object_id"),
    ({"method": "GET", "path": "/api/health", "auth_required": False}, "public"),
    ({"method": "GET", "path": "/api/orders/{order_id}", "path_params": ["order_id"]}, "public"),     # auth unknown: not assumed
])
def test_classification(endpoint, status):
    assert classify(endpoint, OBJECTS)[0] == status


def test_writes_are_classified_as_testable_only_when_allowed():
    put = {"method": "PUT", "path": "/api/orders/{order_id}", "path_params": ["order_id"], "auth_required": True}
    assert classify(put, OBJECTS, allow_write=True)[0] == "tested"


def test_report_counts_and_text():
    report = coverage_report(endpoints_from_openapi(SPEC), OBJECTS)
    assert report["total"] == 8 and report["counts"]["tested"] == 1
    text = format_coverage(report)
    assert "8 operations discovered, 1 tested" in text
    assert "[tested] GET /api/orders/{order_id}" in text and "[multiple_ids]" in text and "[id_in_query]" in text


# -- the adapter -----------------------------------------------------------------------------

def test_from_openapi_tests_only_reads_by_default():
    brains = IdorBrains.from_openapi(SPEC, OBJECTS, use_llm=False)
    objects = brains.surface_map(make_contract())
    assert {o["method"] for o in objects} == {"GET"}                       # PUT and DELETE on the same path are not attacked
    assert {o["endpoint"] for o in objects} == {"/api/orders/1", "/api/orders/2"}


def test_writes_are_attacked_only_when_explicitly_allowed():
    brains = IdorBrains.from_openapi(SPEC, OBJECTS, use_llm=False, allow_write=True)
    assert {o["method"] for o in brains.surface_map(make_contract())} == {"GET", "PUT", "DELETE"}


def test_the_report_says_what_was_not_tested():
    brains = IdorBrains.from_openapi(SPEC, OBJECTS, use_llm=False)
    report = brains.report([])
    assert "No judge-confirmed findings." in report
    assert "8 operations discovered, 1 tested" in report


# -- the real crAPI spec (only if the practice target has been cloned) ----------------------------

CRAPI_SPEC = Path(__file__).resolve().parents[2] / "crapi" / "upstream" / "openapi-spec" / "crapi-openapi-spec.json"


@pytest.mark.skipif(not CRAPI_SPEC.exists(), reason="crapi/upstream not cloned (see crapi/README.md)")
def test_the_real_crapi_spec():
    endpoints = endpoints_from_openapi(CRAPI_SPEC)
    assert len(endpoints) == 44
    found = by_key(endpoints)
    assert found[("GET", "/workshop/api/shop/orders/{order_id}")]["auth_required"] is True
    report = coverage_report(endpoints, {"orders": {"user_A": "6", "user_B": "7"}})
    assert report["counts"]["tested"] == 1
    assert {e["path"] for e in report["entries"] if e["status"] == "id_in_query"} >= {"/workshop/api/mechanic/mechanic_report"}
