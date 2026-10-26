"""Local-only MaaS stub: key validation, self-service list/create/revoke.

This is a development fixture. Keys and state live in memory and reset when
the container restarts. It never talks to a cluster and must not be exposed
outside a developer workstation.
"""

import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# API-key login fixtures.
VALIDATION_IDENTITIES = {
    "local-noy-key": "nitzikow@redhat.com",
    "local-test-user-key": "local-test-user@example.com",
    "local-returning-key": "returning-user@example.com",
}

# username -> list[dict]
KEYS = {}


def now_iso(dt=None):
    return (dt or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")


def seed():
    KEYS["returning-user@example.com"] = [
        {
            "id": "key-returning-main",
            "name": "laptop-claude-code",
            "username": "returning-user@example.com",
            "subscription": "GE",
            "tenant": "models-as-a-service",
            "status": "active",
            "creationDate": now_iso(datetime.now(timezone.utc) - timedelta(days=21)),
            "expirationDate": now_iso(datetime.now(timezone.utc) + timedelta(days=69)),
            "lastUsedAt": now_iso(datetime.now(timezone.utc) - timedelta(hours=2)),
        },
        {
            "id": "key-returning-old",
            "name": "old-laptop",
            "username": "returning-user@example.com",
            "subscription": "GE",
            "tenant": "models-as-a-service",
            "status": "revoked",
            "creationDate": now_iso(datetime.now(timezone.utc) - timedelta(days=140)),
            "expirationDate": now_iso(datetime.now(timezone.utc) - timedelta(days=50)),
            "lastUsedAt": now_iso(datetime.now(timezone.utc) - timedelta(days=60)),
        },
    ]
    KEYS["local-test-user@example.com"] = [
        {
            "id": "key-local-test",
            "name": "local-test",
            "username": "local-test-user@example.com",
            "subscription": "GE",
            "tenant": "models-as-a-service",
            "status": "active",
            "creationDate": now_iso(datetime.now(timezone.utc) - timedelta(days=5)),
            "expirationDate": now_iso(datetime.now(timezone.utc) + timedelta(days=85)),
            "lastUsedAt": "",
        }
    ]


seed()


def parse_go_duration(value, default_hours=2160):
    """Parse the subset of Go durations MaaS accepts: 720h, 30m, 90s."""
    if not value:
        return timedelta(hours=default_hours)
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(h|m|s)", str(value).strip())
    if not match:
        return timedelta(hours=default_hours)
    amount = float(match.group(1))
    unit = match.group(2)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    return timedelta(seconds=amount)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    def _send(self, status, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _username(self):
        return (self.headers.get("X-MaaS-Username") or "").strip()

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        body = self._body()

        if path.endswith("/internal/v1/api-keys/validate"):
            username = VALIDATION_IDENTITIES.get((body or {}).get("key", ""), "")
            self._send(200, {"valid": bool(username), "username": username, "groups": []})
            return

        if path == "/v1/api-keys/search":
            username = self._username()
            if not username:
                username = ((body.get("filters") or {}).get("username") or "").strip()
            keys = [dict(k) for k in KEYS.get(username, []) if k.get("status") != "deleted"]
            self._send(200, {"object": "list", "data": keys, "has_more": False})
            return

        if path == "/v1/api-keys":
            username = self._username()
            if not username:
                self._send(400, {"error": "missing X-MaaS-Username"})
                return
            name = (body.get("name") or "").strip()
            if not name:
                self._send(400, {"error": "name is required"})
                return
            expires = datetime.now(timezone.utc) + parse_go_duration(body.get("expiresIn"))
            key_id = "key-" + uuid.uuid4().hex[:12]
            secret = "sk-oai-local-" + uuid.uuid4().hex
            record = {
                "id": key_id,
                "name": name,
                "username": username,
                "subscription": body.get("subscription") or "GE",
                "tenant": "models-as-a-service",
                "status": "active",
                "creationDate": now_iso(),
                "expirationDate": now_iso(expires),
                "lastUsedAt": "",
                "labels": body.get("labels") or {},
            }
            KEYS.setdefault(username, []).insert(0, record)
            response = dict(record)
            response["key"] = secret
            response["keyPrefix"] = secret[:14] + "…"
            self._send(201, response)
            return

        self._send(404, {"error": "not found"})

    def do_DELETE(self):  # noqa: N802
        path = urlparse(self.path).path
        if not path.startswith("/v1/api-keys/"):
            self._send(404, {"error": "not found"})
            return
        key_id = path.rsplit("/", 1)[-1]
        username = self._username()
        for key in KEYS.get(username, []):
            if key["id"] == key_id:
                key["status"] = "revoked"
                self._send(204)
                return
        self._send(404, {"error": "key not found"})

    def do_GET(self):  # noqa: N802
        self._send(200, {"status": "ok", "service": "local-maas-stub", "keys": len(sum(KEYS.values(), []))})

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
