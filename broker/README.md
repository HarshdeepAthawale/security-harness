# Broker usage

    pip install -r broker/requirements.txt
    python -m pytest broker/tests            # 587 tests; HTTPS tests skip without certs

Generate a ledger signing key (Ed25519, PEM):

    python - <<'PY'
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    open("ledger_signing.key", "wb").write(k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PY
    chmod 600 ledger_signing.key

Run (one JSON plan per stdin line, one JSON result per stdout line):

    chmod 600 broker/examples/credentials.json
    python -m broker.src.service \
        --scope broker/examples/scope.json \
        --credentials broker/examples/credentials.json \
        --ledger ledger.jsonl --signing-key ledger_signing.key \
        < broker/examples/plan.jsonl

Flags for lab targets: --allow-loopback, --allow-private (cloud metadata
addresses stay blocked regardless). On WSL under /mnt/c, file modes are not
real: either keep credentials inside the Linux filesystem (~/), or pass
--allow-loose-file-perms.

Result fields: outcome (response | error | not_sent | internal_error | rejected),
status, expectation (met | unmet | inconclusive), possibly_delivered, request_hash,
digest, sample (redacted), headers (redacted). Rejections return only a code:
invalid_plan | scope_violation | credential_error | body_not_allowed | build_error |
dns_blocked | ledger_unavailable | internal_error.

At startup, pending records with no completion are logged as
"unfinished_pending ... outcome=unknown": the request may have been sent.
