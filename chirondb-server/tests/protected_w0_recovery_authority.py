#!/usr/bin/env python3
"""Exercise a credential revocation across a protected W0 backup frontier.

Run prepare before the offline full backup, advance after restarting the live
installation, and verify against the restored installation. The credential
secret stays in the fixture's private secrets directory and is never logged.
"""

import argparse
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from protected_wlite_mixed import Client


PROBE = "w0-recovery-reader"
KEY = "w0-recovery-suffix-20260929"
SQL = "SQL UPDATE w0_edge_rows SET revision=2 WHERE id=0;"


def request(root, port, token, method, path, body=None):
    context = ssl.create_default_context(cafile=str(root / "ca.pem"))
    payload = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": "Bearer " + token}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    call = Request(f"https://127.0.0.1:{port}{path}", payload, headers, method=method)
    try:
        with urlopen(call, context=context, timeout=30) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def require_status(actual, expected, label):
    if actual != expected:
        raise AssertionError((label, "HTTP status", actual, expected))


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    os.replace(temporary, path)


def prepare(root, port, report_path):
    admin = (root / "secrets" / "admin.key").read_text().strip()
    status, identity = request(root, port, admin, "GET", "/v1/security/whoami")
    require_status(status, 200, "admin identity")
    tenant = identity["tenant"]
    principal = {"id": PROBE, "tenant": tenant, "enabled": True,
                 "attributes": {"department": "Ingestion", "clearance": "internal"},
                 "grants": [{"tenants": [tenant], "collections": ["w0"],
                             "actions": ["read", "search"]}],
                 "installation_actions": [], "delegation": []}
    status, created = request(root, port, admin, "PUT", "/v1/security/principals",
                              {"expected_revision": identity["identity_revision"],
                               "value": principal})
    require_status(status, 200, "create probe principal")
    status, issued = request(root, port, admin, "POST", "/v1/security/credentials",
                             {"expected_revision": created["revision"],
                              "principal": PROBE})
    require_status(status, 200, "issue probe credential")
    key_path = root / "secrets" / "w0-recovery-probe.key"
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(issued["secret"] + "\n")
    status, probe_identity = request(root, port, issued["secret"], "GET",
                                     "/v1/security/whoami")
    require_status(status, 200, "probe credential before backup")
    if probe_identity["principal"] != PROBE:
        raise AssertionError("probe principal mismatch")
    report = {"probe_principal": PROBE, "probe_credential_id": issued["id"],
              "tenant": tenant, "before_backup_revision": issued["revision"],
              "before_backup_probe_status": status}
    save(report_path, report)
    return report


def advance(root, port, report_path):
    report = json.loads(report_path.read_text())
    admin = (root / "secrets" / "admin.key").read_text().strip()
    probe = (root / "secrets" / "w0-recovery-probe.key").read_text().strip()
    client = Client(root, port, "admin", timeout_seconds=300)
    try:
        receipt, _ = client.query(SQL, idempotency_key=KEY)
    finally:
        client.close()
    if not receipt.get("committed") or not receipt.get("transaction_id"):
        raise AssertionError("post-backup SQL suffix did not commit")
    status, identity = request(root, port, admin, "GET", "/v1/security/whoami")
    require_status(status, 200, "admin identity before revoke")
    status, revoked = request(root, port, admin, "POST",
                              f"/v1/security/credentials/{report['probe_credential_id']}/revoke",
                              {"expected_revision": identity["identity_revision"]})
    require_status(status, 200, "revoke probe credential")
    status, _ = request(root, port, probe, "GET", "/v1/security/whoami")
    require_status(status, 401, "revoked credential on live installation")
    report.update({"post_backup_transaction_id": receipt["transaction_id"],
                   "after_revoke_revision": revoked["revision"],
                   "after_revoke_probe_status": status})
    save(report_path, report)
    return report


def verify(root, port, report_path):
    report = json.loads(report_path.read_text())
    probe = (root / "secrets" / "w0-recovery-probe.key").read_text().strip()
    status, _ = request(root, port, probe, "GET", "/v1/security/whoami")
    require_status(status, 401, "revoked credential after restore")
    client = Client(root, port, "admin", timeout_seconds=300)
    try:
        receipt, _ = client.query(SQL, idempotency_key=KEY)
        points, _ = client.query("COUNT w0;")
    finally:
        client.close()
    if receipt.get("transaction_id") != report["post_backup_transaction_id"]:
        raise AssertionError("post-backup idempotency decision changed on restore")
    if points["rows"][0]["count"] != 100000:
        raise AssertionError("W0 vector count changed on restore")
    report.update({"restored_probe_status": status,
                   "restored_transaction_id": receipt["transaction_id"],
                   "restored_vector_count": points["rows"][0]["count"]})
    save(report_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "advance", "verify"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = {"prepare": prepare, "advance": advance, "verify": verify}[args.phase](
        args.root, args.port, args.report)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
