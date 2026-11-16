"""Single source of truth for size limits. plan.py, executor.py, redact.py
and ledger.py import from here; do not redefine these elsewhere."""

# Plan input
MAX_PLAN_BYTES = 64 * 1024
MAX_PATH_BYTES = 2048
MAX_HEADER_COUNT = 30
MAX_HEADER_NAME_LENGTH = 256
MAX_HEADER_VALUE_LENGTH = 8192
MAX_QUERY_PARAMS = 50
MAX_QUERY_BYTES = 100_000
MAX_BODY_BYTES = 1_000_000

# Responses / audit
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SAMPLE_BYTES = 4096
MAX_REDACT_INPUT_BYTES = 1024 * 1024
MAX_LEDGER_RECORD_BYTES = 4 * 1024 * 1024
