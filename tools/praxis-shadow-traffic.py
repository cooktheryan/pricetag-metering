#!/usr/bin/env python3
"""PriceTag-only traffic watcher for the Praxis upgrade sequence.

No-argument mode runs one unified test:
  * 96 synthetic users distributed across the normal OpenAI and Anthropic
    llm-katan echo routes;
  * one low-rate real GLM user through the normal PriceTag gateway.

The process never targets a shadow URL and never changes route weights.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import curses
import hashlib
import json
import math
import random
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MAX_USERS = 100
DEFAULT_CONTEXT = "ai-gateway-dogfood/c117-e-us-south-containers-cloud-ibm-com:30087/IAM#yovadia@redhat.com"
DEFAULT_SERVER = "https://c117-e.us-south.containers.cloud.ibm.com:30087"
DEFAULT_NAMESPACE = "ai-gateway-dogfood"
DEFAULT_OPENAI_ROUTE = "ai-gateway-openai-echo"
DEFAULT_ANTHROPIC_ROUTE = "ai-gateway-glm-echo"
DEFAULT_GATEWAY_ROUTE = "ai-gateway"
DEFAULT_OPENAI_URL = "https://ai-gateway-openai-echo-ai-gateway-dogfood.dogfood-us-south-1-bxf-4x-f196230f74f7ff44a5b4eeb1003c5bd5-0000.us-south.containers.appdomain.cloud"
DEFAULT_ANTHROPIC_URL = "https://ai-gateway-glm-echo-ai-gateway-dogfood.dogfood-us-south-1-bxf-4x-f196230f74f7ff44a5b4eeb1003c5bd5-0000.us-south.containers.appdomain.cloud"
DEFAULT_GATEWAY_URL = "https://ai-gateway-ai-gateway-dogfood.dogfood-us-south-1-bxf-4x-f196230f74f7ff44a5b4eeb1003c5bd5-0000.us-south.containers.appdomain.cloud"
DEFAULT_ECHO_MODEL = "benchmark-echo"
DEFAULT_GLM_MODEL = "rits/zai-org/glm-5-3"
FORBIDDEN_MARKER = "enmaas"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Lane:
    name: str
    provider: str
    model: str
    base_url: str
    path: str
    protocol: str
    synthetic: bool
    interval: float


@dataclass(frozen=True)
class UserSpec:
    label: str
    key: str
    lane: Lane


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def reject_enmaas(field: str, value: str) -> None:
    compact = value.casefold().replace("-", "").replace("_", "")
    if FORBIDDEN_MARKER in compact:
        raise ConfigError(f"{field} contains a forbidden EnMaaS marker")


def safe_url(field: str, value: str) -> str:
    value = value.strip().rstrip("/")
    reject_enmaas(field, value)
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError(f"{field} must be an HTTPS URL with a hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{field} must not contain credentials, query, or fragment data")
    return value


def oc_run(args: argparse.Namespace, command: list[str]) -> str:
    if shutil.which("oc") is None:
        raise ConfigError("oc is not installed")
    full = ["oc", "--context", args.oc_context, "--server", args.oc_server, *command]
    try:
        completed = subprocess.run(full, capture_output=True, text=True, timeout=20, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ConfigError("oc read-only check timed out") from exc
    if completed.returncode != 0:
        raise ConfigError("oc read-only check failed")
    return completed.stdout.strip()


def preflight_price_tag(args: argparse.Namespace) -> None:
    try:
        observed = oc_run(args, ["whoami", "--show-server"]).rstrip("/")
        if observed != args.oc_server:
            raise ConfigError("oc reported a different server")
        oc_run(args, ["get", "namespace", args.namespace, "-o", "name"])
    except ConfigError as exc:
        raise ConfigError(
            "PriceTag oc login/namespace check failed; log in to the PriceTag "
            f"context and ensure namespace {args.namespace!r} is accessible"
        ) from exc


def route_info(args: argparse.Namespace, name: str) -> dict[str, str]:
    try:
        raw = json.loads(oc_run(args, ["get", "route", name, "-o", "json"]))
    except (ConfigError, json.JSONDecodeError) as exc:
        raise ConfigError(f"PriceTag route {name!r} was not found") from exc
    host = raw.get("spec", {}).get("host", "")
    target = raw.get("spec", {}).get("to", {}).get("name", "")
    if not host or not target:
        raise ConfigError(f"PriceTag route {name!r} is incomplete")
    return {"host": host, "target": target}


def ensure_key(args: argparse.Namespace) -> Path:
    path = Path(args.key_file).expanduser()
    if not path.is_file():
        raise ConfigError(f"PriceTag key file not found: {path}; create ~/.mykey or override --key-file")
    if not path.read_text(encoding="utf-8").strip():
        raise ConfigError(f"PriceTag key file is empty: {path}")
    return path


def endpoint(args: argparse.Namespace, route_name: str, override: str | None, fallback: str) -> str:
    try:
        info = route_info(args, route_name)
        if info["target"] != "praxis":
            raise ConfigError(f"route {route_name!r} does not target praxis")
        return safe_url(route_name, f"https://{info['host']}")
    except ConfigError:
        return safe_url(route_name, override or fallback)


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    preflight_price_tag(args)
    openai_url = endpoint(args, args.openai_route, args.openai_url, DEFAULT_OPENAI_URL)
    anthropic_url = endpoint(args, args.anthropic_route, args.anthropic_url, DEFAULT_ANTHROPIC_URL)
    gateway_url = endpoint(args, args.gateway_route, args.gateway_url, DEFAULT_GATEWAY_URL)
    if args.phase == "canary":
        for resource in ("deployment/praxis-shadow", "service/praxis-shadow"):
            try:
                oc_run(args, ["get", resource, "-o", "name"])
            except ConfigError as exc:
                raise ConfigError(f"canary requires PriceTag resource {resource!r}") from exc
    return {"openai_url": openai_url, "anthropic_url": anthropic_url, "gateway_url": gateway_url}


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))]


class Metrics:
    def __init__(self, users: list[UserSpec], window_seconds: float) -> None:
        self.lock = threading.Lock()
        self.window_seconds = window_seconds
        self.users = {
            user.label: {
                "user": user.label,
                "lane": user.lane.name,
                "provider": user.lane.provider,
                "model": user.lane.model,
                "sent": 0,
                "responses": 0,
                "ok": 0,
                "drops": 0,
                "in_flight": False,
                "last": "never",
                "last_status": None,
                "last_backend": "unknown",
                "last_latency_ms": None,
                "samples": deque(maxlen=4000),
            }
            for user in users
        }
        self.statuses: Counter[str] = Counter()

    def mark_sent(self, user: str) -> bool:
        with self.lock:
            row = self.users[user]
            if row["in_flight"]:
                return False
            row["in_flight"] = True
            row["sent"] += 1
            return True

    def record(self, event: dict[str, Any]) -> None:
        with self.lock:
            row = self.users[event["user"]]
            row["in_flight"] = False
            row["last"] = str(event["status"]) if event["status"] is not None else "drop"
            row["last_status"] = event["status"]
            row["last_backend"] = event["backend"]
            row["last_latency_ms"] = event["latency_ms"]
            row["samples"].append((time.monotonic(), event["latency_ms"]))
            if event["status"] is not None:
                row["responses"] += 1
                self.statuses[str(event["status"])] += 1
            if event["outcome"] == "ok":
                row["ok"] += 1
            if event["outcome"] == "drop":
                row["drops"] += 1

    def snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        cutoff = time.monotonic() - self.window_seconds
        with self.lock:
            samples: list[float] = []
            rows: list[dict[str, Any]] = []
            for row in self.users.values():
                while row["samples"] and row["samples"][0][0] < cutoff:
                    row["samples"].popleft()
                current = [value for _, value in row["samples"]]
                samples.extend(current)
                rows.append({key: value for key, value in row.items() if key != "samples"})
            sent = sum(row["sent"] for row in self.users.values())
            responses = sum(row["responses"] for row in self.users.values())
            drops = sum(row["drops"] for row in self.users.values())
            successful = sum(row["ok"] for row in self.users.values())
            return {
                "sent": sent,
                "responses": responses,
                "drops": drops,
                "availability_pct": (successful / sent * 100.0) if sent else 0.0,
                "in_flight": sum(1 for row in self.users.values() if row["in_flight"]),
                "status_codes": dict(sorted(self.statuses.items())),
                "p50_ms": percentile(samples, 0.50),
                "p95_ms": percentile(samples, 0.95),
                "p99_ms": percentile(samples, 0.99),
            }, rows


def discard_body(stream: Any) -> None:
    while stream.read(8192):
        pass


def backend_from_headers(headers: Any, args: argparse.Namespace) -> str:
    for name in args.marker_headers:
        value = headers.get(name, "").strip().casefold()
        if value in {"shadow", "new", "canary"} or "shadow" in value:
            return "shadow"
        if value in {"praxis", "main", "old", "baseline"}:
            return "praxis"
    return "praxis" if args.phase == "baseline" else "unknown"


def request_once(user: UserSpec, args: argparse.Namespace, sequence: int) -> dict[str, Any]:
    lane = user.lane
    max_tokens = random.randint(1, 32) if lane.synthetic else 1
    body = {
        "model": lane.model,
        "messages": [{"role": "user", "content": "echo"}],
        "max_tokens": max_tokens,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "praxis-shadow-traffic/1",
        "X-Request-ID": f"praxis-shadow-{user.label}-{sequence}",
    }
    if lane.protocol == "openai":
        headers["Authorization"] = f"Bearer {user.key}"
    else:
        headers.update({"x-api-key": user.key, "anthropic-version": "2023-06-01"})
    request = urllib.request.Request(lane.base_url + lane.path, data=json.dumps(body).encode(), method="POST", headers=headers)
    event: dict[str, Any] = {
        "event": "request_result", "at": now_utc(), "user": user.label,
        "lane": lane.name, "provider": lane.provider, "model": lane.model,
        "max_tokens": max_tokens, "status": None, "outcome": "drop",
        "backend": "unknown", "error_class": None, "latency_ms": 0.0,
    }
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=args.timeout, context=ssl.create_default_context()) as response:
            discard_body(response)
            event["status"] = response.status
            event["backend"] = backend_from_headers(response.headers, args)
            if 200 <= response.status < 300:
                event["outcome"] = "ok"
            else:
                event["error_class"] = str(response.status)
    except urllib.error.HTTPError as exc:
        discard_body(exc)
        event["status"] = exc.code
        event["backend"] = backend_from_headers(exc.headers, args)
        event["error_class"] = str(exc.code)
    except TimeoutError:
        event["error_class"] = "timeout"
    except urllib.error.URLError:
        event["error_class"] = "transport_error"
    except Exception:
        event["error_class"] = "request_error"
    event["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
    return event


def scheduler_drop(user: UserSpec) -> dict[str, Any]:
    return {
        "event": "scheduler_drop", "at": now_utc(), "user": user.label,
        "lane": user.lane.name, "provider": user.lane.provider, "model": user.lane.model,
        "status": None, "outcome": "drop", "backend": "unknown",
        "error_class": "in_flight", "latency_ms": 0.0,
    }


def draw_dashboard(stdscr: Any, metrics: Metrics, started: float, page: int, page_size: int) -> int:
    stdscr.erase()
    stdscr.timeout(200)
    overall, users = metrics.snapshot()
    height, width = stdscr.getmaxyx()
    counts = Counter(row["lane"] for row in users)
    header = [
        "PRAXIS UPGRADE TRAFFIC — PriceTag llm-katan echo + real GLM",
        f"elapsed {time.monotonic() - started:7.1f}s  sent {overall['sent']:,}  responses {overall['responses']:,}  drops {overall['drops']:,}  availability {overall['availability_pct']:.2f}%",
        f"latency p50/p95/p99 {overall['p50_ms']:.0f}/{overall['p95_ms']:.0f}/{overall['p99_ms']:.0f} ms  status {overall['status_codes']}  in-flight {overall['in_flight']}",
        "lanes " + "  ".join(f"{lane}={count}" for lane, count in counts.items()),
        "─" * max(1, width - 1),
        "USER             LANE       PROVIDER   MODEL              BACKEND  SENT RESP DROP LAST LATENCY",
    ]
    availability_attr = curses.color_pair(1) | curses.A_BOLD if overall["availability_pct"] >= 99.5 else curses.color_pair(3) | curses.A_BOLD if overall["availability_pct"] >= 95 else curses.color_pair(2) | curses.A_BOLD
    attrs = [curses.color_pair(4) | curses.A_BOLD, availability_attr, curses.A_DIM, curses.color_pair(6), curses.color_pair(4), curses.color_pair(4) | curses.A_BOLD]
    usable = max(1, height - len(header) - 2)
    visible = min(page_size if page_size > 0 else usable, usable)
    pages = max(1, math.ceil(len(users) / visible))
    page %= pages
    shown = users[page * visible : (page + 1) * visible]
    for y, line in enumerate(header):
        try:
            stdscr.addnstr(y, 0, line, max(0, width - 1), attrs[y])
        except curses.error:
            pass
    for offset, row in enumerate(shown):
        y = len(header) + offset
        prefix = f"{row['user']:<17.17} {row['lane']:<10.10} {row['provider']:<10.10} {row['model']:<18.18}"
        backend = f" {row['last_backend']:<8.8}"
        counts_text = f" {row['sent']:>4} {row['responses']:>4} {row['drops']:>4} "
        status = str(row["last"])
        status_attr = curses.color_pair(2) | curses.A_BOLD if status == "drop" or (row["last_status"] is not None and row["last_status"] >= 500) else curses.color_pair(1) | curses.A_BOLD if row["last_status"] is not None and 200 <= row["last_status"] < 300 else curses.color_pair(3) if row["last_status"] is not None else 0
        backend_attr = curses.color_pair(5) | curses.A_BOLD if row["last_backend"] == "shadow" else curses.color_pair(4) if row["last_backend"] == "praxis" else curses.color_pair(3)
        suffix = f"{status:<4.4} {str(row['last_latency_ms'] or 0):>7}ms"
        try:
            stdscr.addnstr(y, 0, prefix, max(0, width - 1))
            stdscr.addnstr(y, len(prefix), backend, max(0, width - len(prefix) - 1), backend_attr)
            start = len(prefix) + len(backend)
            stdscr.addnstr(y, start, counts_text, max(0, width - start - 1))
            start += len(counts_text)
            stdscr.addnstr(y, start, suffix, max(0, width - start - 1), status_attr)
        except curses.error:
            pass
    try:
        stdscr.addnstr(len(header) + len(shown), 0, f"page {page + 1}/{pages}  ←/→ page  q quit", max(0, width - 1))
    except curses.error:
        pass
    stdscr.refresh()
    key = stdscr.getch()
    if key in (ord("q"), ord("Q")):
        return -1
    if key in (curses.KEY_RIGHT, ord("n")):
        return page + 1
    if key in (curses.KEY_LEFT, ord("p")):
        return page - 1
    return page


def write_event(stream: Any, event: dict[str, Any]) -> None:
    stream.write(json.dumps(event, sort_keys=True) + "\n")
    stream.flush()


def run_loop(stdscr: Any, args: argparse.Namespace, users: list[UserSpec], metrics: Metrics, executor: concurrent.futures.ThreadPoolExecutor, stream: Any, started: float, deadline: float) -> None:
    if stdscr is not None:
        try:
            curses.start_color(); curses.use_default_colors(); stdscr.bkgdset(" ", curses.color_pair(0))
            curses.init_pair(1, curses.COLOR_GREEN, -1); curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1); curses.init_pair(4, curses.COLOR_CYAN, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1); curses.init_pair(6, curses.COLOR_WHITE, -1)
        except curses.error:
            pass
        stdscr.clear(); stdscr.refresh()
    due = {user.label: started + (int.from_bytes(hashlib.sha256(user.label.encode()).digest()[:4], "big") / 2**32) * user.lane.interval for user in users}
    pending: dict[concurrent.futures.Future[dict[str, Any]], UserSpec] = {}
    sequence = 0; page = 0; next_stats = started; stop = False
    while (time.monotonic() < deadline and not stop) or pending:
        now = time.monotonic()
        if now < deadline and not stop:
            for user in users:
                if now < due[user.label]:
                    continue
                due[user.label] = now + user.lane.interval
                if metrics.mark_sent(user.label):
                    sequence += 1
                    pending[executor.submit(request_once, user, args, sequence)] = user
                else:
                    event = scheduler_drop(user); metrics.record(event); write_event(stream, event)
        for future in [item for item in pending if item.done()]:
            user = pending.pop(future); event = future.result(); metrics.record(event); write_event(stream, event)
        if stdscr is not None:
            page = draw_dashboard(stdscr, metrics, started, page, args.page_size); stop = page < 0
        elif now >= next_stats:
            overall, _ = metrics.snapshot()
            print(f"sent={overall['sent']} responses={overall['responses']} drops={overall['drops']} availability={overall['availability_pct']:.2f}% p50/p95/p99={overall['p50_ms']:.0f}/{overall['p95_ms']:.0f}/{overall['p99_ms']:.0f}ms status={overall['status_codes']}", flush=True)
            next_stats = now + args.stats_interval
        time.sleep(0.02)
    for future in list(pending):
        event = future.result(); metrics.record(event); write_event(stream, event)


def run_traffic(args: argparse.Namespace, plan: dict[str, Any], key_path: Path) -> int:
    key = key_path.read_text(encoding="utf-8").strip()
    openai_lane = Lane("openai-echo", "openai", args.openai_model, plan["openai_url"], "/v1/chat/completions", "openai", True, args.interval)
    anthropic_lane = Lane("glm-echo", "anthropic", args.echo_model, plan["anthropic_url"], "/v1/messages", "anthropic", True, args.interval)
    glm_lane = Lane("real-glm", "anthropic", args.glm_model, plan["gateway_url"], "/v1/messages", "anthropic", False, args.glm_interval)
    lanes = (openai_lane, anthropic_lane)
    users = [
        UserSpec(f"shadow-user-{index:03d}", key, lanes[(index - 1) % len(lanes)])
        for index in range(1, args.user_count + 1)
    ]
    users.insert(0, UserSpec("real-glm", key, glm_lane))
    metrics = Metrics(users, args.window_seconds)
    evidence = Path(args.evidence).expanduser(); evidence.parent.mkdir(parents=True, exist_ok=True)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(args.concurrency, len(users)))
    started = time.monotonic(); deadline = started + args.duration
    use_ui = args.ui == "always" or (args.ui == "auto" and sys.stdout.isatty() and sys.stdin.isatty())
    start_event = {
        "event": "run_start", "at": now_utc(), "phase": args.phase,
        "gateway_url_host": urlsplit(plan["gateway_url"]).hostname,
        "openai_echo_url_host": urlsplit(plan["openai_url"]).hostname,
        "glm_echo_url_host": urlsplit(plan["anthropic_url"]).hostname,
        "users": args.user_count, "real_glm_users": 1, "retries": 0,
        "lanes": [{"lane": lane.name, "provider": lane.provider, "model": lane.model} for lane in (openai_lane, anthropic_lane, glm_lane)],
    }
    try:
        with evidence.open("w", encoding="utf-8") as stream:
            write_event(stream, start_event)
            if use_ui:
                curses.wrapper(lambda stdscr: run_loop(stdscr, args, users, metrics, executor, stream, started, deadline))
            else:
                run_loop(None, args, users, metrics, executor, stream, started, deadline)
            overall, _ = metrics.snapshot(); write_event(stream, {"event": "run_end", "at": now_utc(), **overall})
    finally:
        executor.shutdown(wait=True)
    print(f"evidence={evidence}")
    return 0


def dry_run_plan(args: argparse.Namespace, plan: dict[str, Any], key_path: Path) -> dict[str, Any]:
    return {
        "status": "dry-run-ready", "network": "disabled", "cluster_mutation": "disabled",
        "phase": args.phase, "oc_preflight": "read-only PriceTag checks completed",
        "namespace": args.namespace, "key_file": str(key_path), "users": args.user_count,
        "real_glm_users": 1, "retries": 0,
        "lanes": [
            {"lane": "openai-echo", "provider": "openai", "model": args.openai_model, "interval": args.interval},
            {"lane": "glm-echo", "provider": "anthropic", "model": args.echo_model, "interval": args.interval},
            {"lane": "real-glm", "provider": "anthropic", "model": args.glm_model, "interval": args.glm_interval},
        ],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="PriceTag-only Praxis llm-katan traffic watcher")
    result.add_argument("--phase", choices=("baseline", "canary"), default="baseline")
    result.add_argument("--oc-context", default=DEFAULT_CONTEXT); result.add_argument("--oc-server", default=DEFAULT_SERVER)
    result.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    result.add_argument("--openai-route", default=DEFAULT_OPENAI_ROUTE); result.add_argument("--anthropic-route", default=DEFAULT_ANTHROPIC_ROUTE)
    result.add_argument("--gateway-route", default=DEFAULT_GATEWAY_ROUTE)
    result.add_argument("--openai-url"); result.add_argument("--anthropic-url"); result.add_argument("--gateway-url")
    result.add_argument("--openai-model", default=DEFAULT_ECHO_MODEL); result.add_argument("--echo-model", default=DEFAULT_GLM_MODEL)
    result.add_argument("--glm-model", default=DEFAULT_GLM_MODEL); result.add_argument("--key-file", default="~/.mykey")
    result.add_argument("--user-count", type=int, default=96); result.add_argument("--interval", type=float, default=5.0)
    result.add_argument("--glm-interval", type=float, default=30.0); result.add_argument("--timeout", type=float, default=20.0)
    result.add_argument("--duration", type=float, default=300.0); result.add_argument("--concurrency", type=int, default=32)
    result.add_argument("--window-seconds", type=float, default=60.0); result.add_argument("--stats-interval", type=float, default=5.0)
    result.add_argument("--marker-headers", type=lambda value: [item.strip() for item in value.split(",") if item.strip()], default=["x-praxis-lane", "x-gateway-build"])
    result.add_argument("--evidence", default=f"/tmp/praxis-shadow-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl")
    result.add_argument("--ui", choices=("auto", "always", "never"), default="auto"); result.add_argument("--page-size", type=int, default=0)
    result.add_argument("--dry-run", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if not 1 <= args.user_count <= MAX_USERS:
            raise ConfigError(f"--user-count must be between 1 and {MAX_USERS}")
        if min(args.duration, args.interval, args.glm_interval, args.timeout, args.concurrency) <= 0:
            raise ConfigError("duration, intervals, timeout, and concurrency must be positive")
        args.oc_server = safe_url("PriceTag server", args.oc_server)
        reject_enmaas("PriceTag context", args.oc_context); reject_enmaas("PriceTag namespace", args.namespace)
        key_path = ensure_key(args); plan = prepare(args)
        if args.dry_run:
            print(json.dumps(dry_run_plan(args, plan, key_path), indent=2, sort_keys=True)); return 0
        return run_traffic(args, plan, key_path)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
