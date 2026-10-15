#!/usr/bin/env python3
"""PriceTag-only traffic watcher for the Praxis upgrade sequence.

Default mode is a five-minute baseline run through the normal PriceTag
Benchmark route, backed by llm-katan.  Canary mode still sends to that normal
route; route weights decide whether Praxis or Praxis Shadow serves a request.
This script never changes route weights or creates/deletes resources.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import curses
import hashlib
import json
import math
import os
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
DEFAULT_ROUTE = "ai-gateway-benchmark"
DEFAULT_SHADOW_ROUTE = "ai-gateway-benchmark-shadow"
DEFAULT_GATEWAY_URL = "https://ai-gateway-ai-gateway-dogfood.dogfood-us-south-1-bxf-4x-f196230f74f7ff44a5b4eeb1003c5bd5-0000.us-south.containers.appdomain.cloud"
DEFAULT_BENCHMARK_URL = "https://ai-gateway-benchmark-ai-gateway-dogfood.dogfood-us-south-1-bxf-4x-f196230f74f7ff44a5b4eeb1003c5bd5-0000.us-south.containers.appdomain.cloud"
DEFAULT_MODEL = "benchmark-echo"
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


@dataclass(frozen=True)
class UserSpec:
    label: str
    key: str
    lane: Lane
    interval: float


@dataclass(frozen=True)
class MatrixProbe:
    name: str
    provider: str
    model: str
    path: str
    method: str
    body: dict[str, Any]


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


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    preflight_price_tag(args)
    try:
        benchmark_route = route_info(args, args.route_name)
        benchmark_url = safe_url("PriceTag Benchmark route", f"https://{benchmark_route['host']}")
    except ConfigError:
        benchmark_url = safe_url("PriceTag Benchmark route", args.benchmark_url or DEFAULT_BENCHMARK_URL)
        benchmark_route = {"host": urlsplit(benchmark_url).hostname or "", "target": "fallback"}
    if benchmark_route["target"] not in {"praxis", "fallback"}:
        raise ConfigError(f"normal PriceTag Benchmark route does not target praxis: {benchmark_route['target']!r}")

    try:
        gateway_route = route_info(args, args.gateway_route_name)
        gateway_url = safe_url("PriceTag gateway", f"https://{gateway_route['host']}")
    except ConfigError:
        gateway_url = safe_url("PriceTag gateway", args.gateway_url or DEFAULT_GATEWAY_URL)
        gateway_route = {"host": urlsplit(gateway_url).hostname or "", "target": "fallback"}
    if gateway_route["target"] not in {"praxis", "fallback", "override"}:
        raise ConfigError(f"normal PriceTag gateway route does not target praxis: {gateway_route['target']!r}")

    matrix_routes: dict[str, dict[str, str]] = {}
    if args.real_matrix:
        for key, route_name in (
            ("messages", "ai-gateway"),
            ("chat", "ai-gateway-chat-completions"),
            ("responses", "ai-gateway-responses"),
            ("conversations", "ai-gateway-conversations"),
        ):
            matrix_routes[key] = route_info(args, route_name)
            if matrix_routes[key]["target"] != "praxis":
                raise ConfigError(f"matrix route {route_name!r} does not target praxis")

    shadow: dict[str, str] | None = None
    if args.phase == "canary":
        for resource in ("deployment/praxis-shadow", "service/praxis-shadow"):
            try:
                oc_run(args, ["get", resource, "-o", "name"])
            except ConfigError as exc:
                raise ConfigError(f"canary requires PriceTag resource {resource!r}") from exc
        shadow = route_info(args, args.shadow_route_name)
        if shadow["target"] != "praxis-shadow":
            raise ConfigError(f"shadow route does not target praxis-shadow: {shadow['target']!r}")

    return {
        "gateway_url": gateway_url,
        "benchmark_url": benchmark_url,
        "gateway_route": gateway_route,
        "benchmark_route": benchmark_route,
        "matrix_routes": matrix_routes,
        "shadow_route": shadow,
        "route_source": "oc" if gateway_route["target"] == "praxis" else "fallback/override",
    }


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
            overall = {
                "sent": sent,
                "responses": responses,
                "drops": drops,
                "availability_pct": (successful / sent * 100.0) if sent else 0.0,
                "in_flight": sum(1 for row in self.users.values() if row["in_flight"]),
                "status_codes": dict(sorted(self.statuses.items())),
                "p50_ms": percentile(samples, 0.50),
                "p95_ms": percentile(samples, 0.95),
                "p99_ms": percentile(samples, 0.99),
            }
            return overall, rows


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
    max_tokens = random.randint(1, 5000) if lane.name == "benchmark" else 1
    body = {
        "model": lane.model,
        "messages": [{"role": "user", "content": "echo"}],
        "max_tokens": max_tokens,
    }
    request = urllib.request.Request(
        lane.base_url + lane.path,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "praxis-shadow-traffic/1",
            "X-Request-ID": f"praxis-shadow-{user.label}-{sequence}",
            "x-api-key": user.key,
            "anthropic-version": "2023-06-01",
        },
    )
    started = time.monotonic()
    event: dict[str, Any] = {
        "event": "request_result",
        "at": now_utc(),
        "user": user.label,
        "lane": lane.name,
        "provider": lane.provider,
        "model": lane.model,
        "status": None,
        "outcome": "drop",
        "backend": "unknown",
        "error_class": None,
        "latency_ms": 0.0,
        "max_tokens": max_tokens,
    }
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


def matrix_request(probe: MatrixProbe, gateway_url: str, key: str, args: argparse.Namespace) -> dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "praxis-shadow-matrix/1",
        "X-Request-ID": f"praxis-shadow-matrix-{probe.name}",
    }
    if probe.provider == "anthropic":
        headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
    else:
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(
        gateway_url + probe.path,
        data=json.dumps(probe.body).encode("utf-8"),
        method=probe.method,
        headers=headers,
    )
    event: dict[str, Any] = {
        "event": "matrix_result",
        "at": now_utc(),
        "user": f"matrix-{probe.name}",
        "lane": probe.name,
        "provider": probe.provider,
        "model": probe.model,
        "status": None,
        "outcome": "drop",
        "backend": "unknown",
        "error_class": None,
        "latency_ms": 0.0,
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
    lane = user.lane
    return {
        "event": "scheduler_drop",
        "at": now_utc(),
        "user": user.label,
        "lane": lane.name,
        "provider": lane.provider,
        "model": lane.model,
        "status": None,
        "outcome": "drop",
        "backend": "unknown",
        "error_class": "in_flight",
        "latency_ms": 0.0,
    }


def draw_dashboard(stdscr: Any, metrics: Metrics, started: float, page: int, page_size: int, matrix_line: str) -> int:
    stdscr.erase()
    stdscr.timeout(200)
    overall, users = metrics.snapshot()
    height, width = stdscr.getmaxyx()
    header = [
        "PRAXIS UPGRADE TRAFFIC — PriceTag normal routes",
        f"elapsed {time.monotonic() - started:7.1f}s  sent {overall['sent']:,}  responses {overall['responses']:,}  drops {overall['drops']:,}  availability {overall['availability_pct']:.2f}%",
        f"latency p50/p95/p99 {overall['p50_ms']:.0f}/{overall['p95_ms']:.0f}/{overall['p99_ms']:.0f} ms  status {overall['status_codes']}  in-flight {overall['in_flight']}",
        "─" * max(1, width - 1),
        "USER             LANE       PROVIDER   MODEL              BACKEND  SENT RESP DROP LAST LATENCY",
    ]
    availability_attr = (
        curses.color_pair(1) | curses.A_BOLD
        if overall["availability_pct"] >= 99.5
        else curses.color_pair(3) | curses.A_BOLD
        if overall["availability_pct"] >= 95
        else curses.color_pair(2) | curses.A_BOLD
    )
    header_attrs = [curses.color_pair(4) | curses.A_BOLD, availability_attr, curses.A_DIM, curses.color_pair(4), curses.color_pair(4) | curses.A_BOLD]
    if matrix_line:
        header.insert(3, matrix_line)
        header_attrs.insert(3, curses.color_pair(6))
    usable = max(1, height - len(header) - 2)
    visible = min(page_size if page_size > 0 else usable, usable)
    pages = max(1, math.ceil(len(users) / visible))
    page = page % pages
    shown = users[page * visible : (page + 1) * visible]
    for y, line in enumerate(header):
        try:
            stdscr.addnstr(y, 0, line, max(0, width - 1), header_attrs[y])
        except curses.error:
            pass
    for offset, row in enumerate(shown):
        y = len(header) + offset
        prefix = f"{row['user']:<17.17} {row['lane']:<10.10} {row['provider']:<10.10} {row['model']:<18.18}"
        backend = f" {row['last_backend']:<8.8}"
        counts = f" {row['sent']:>4} {row['responses']:>4} {row['drops']:>4} "
        status = str(row["last"])
        if status == "drop" or (row["last_status"] is not None and row["last_status"] >= 500):
            attr = curses.color_pair(2) | curses.A_BOLD
        elif row["last_status"] is not None and 200 <= row["last_status"] < 300:
            attr = curses.color_pair(1) | curses.A_BOLD
        elif row["last_status"] is not None:
            attr = curses.color_pair(3)
        else:
            attr = 0
        suffix = f"{status:<4.4} {str(row['last_latency_ms'] or 0):>7}ms"
        backend_attr = (
            curses.color_pair(5) | curses.A_BOLD
            if row["last_backend"] == "shadow"
            else curses.color_pair(4)
            if row["last_backend"] == "praxis"
            else curses.color_pair(3)
        )
        try:
            stdscr.addnstr(y, 0, prefix, max(0, width - 1))
            stdscr.addnstr(y, len(prefix), backend, max(0, width - len(prefix) - 1), backend_attr)
            counts_start = len(prefix) + len(backend)
            stdscr.addnstr(y, counts_start, counts, max(0, width - counts_start - 1))
            status_start = counts_start + len(counts)
            stdscr.addnstr(y, status_start, suffix, max(0, width - status_start - 1), attr)
        except curses.error:
            pass
    footer = f"page {page + 1}/{pages}  ←/→ page  q quit"
    try:
        stdscr.addnstr(len(header) + len(shown), 0, footer, max(0, width - 1))
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


def print_summary(metrics: Metrics) -> None:
    overall, _ = metrics.snapshot()
    print(
        f"sent={overall['sent']} responses={overall['responses']} drops={overall['drops']} "
        f"availability={overall['availability_pct']:.2f}% "
        f"p50/p95/p99={overall['p50_ms']:.0f}/{overall['p95_ms']:.0f}/{overall['p99_ms']:.0f}ms "
        f"status={overall['status_codes']}",
        flush=True,
    )


def write_event(stream: Any, event: dict[str, Any]) -> None:
    stream.write(json.dumps(event, sort_keys=True) + "\n")
    stream.flush()


def matrix_probes(args: argparse.Namespace) -> list[MatrixProbe]:
    return [
        MatrixProbe(
            "messages", "anthropic", args.messages_model, "/v1/messages", "POST",
            {"model": args.messages_model, "max_tokens": 1, "messages": [{"role": "user", "content": "echo"}]},
        ),
        MatrixProbe(
            "chat-completions", "openai", args.chat_model, "/v1/chat/completions", "POST",
            {"model": args.chat_model, "max_tokens": 1, "messages": [{"role": "user", "content": "echo"}]},
        ),
        MatrixProbe(
            "responses", "openai", args.responses_model, "/v1/responses", "POST",
            {"model": args.responses_model, "input": "echo", "max_output_tokens": 1},
        ),
        MatrixProbe("conversations", "openai", "local", "/v1/conversations", "POST", {}),
    ]


def run_matrix(args: argparse.Namespace, plan: dict[str, Any], key: str, stream: Any) -> str:
    results: list[dict[str, Any]] = []
    for probe in matrix_probes(args):
        result = matrix_request(probe, plan["gateway_url"], key, args)
        results.append(result)
        write_event(stream, result)
    summary = "matrix " + " ".join(
        f"{result['lane']}={result['status'] if result['status'] is not None else result['error_class']}@{result['backend']}"
        for result in results
    )
    print(summary, flush=True)
    return summary


def run_loop(
    stdscr: Any,
    args: argparse.Namespace,
    users: list[UserSpec],
    metrics: Metrics,
    executor: concurrent.futures.ThreadPoolExecutor,
    stream: Any,
    started: float,
    deadline: float,
    matrix_line: str,
) -> None:
    if stdscr is not None:
        try:
            curses.start_color()
            curses.use_default_colors()
            stdscr.bkgdset(" ", curses.color_pair(0))
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            curses.init_pair(6, curses.COLOR_WHITE, -1)
        except curses.error:
            pass
        stdscr.clear()
        stdscr.refresh()
    due = {
        user.label: started + (int.from_bytes(hashlib.sha256(user.label.encode()).digest()[:4], "big") / 2**32) * user.interval
        for user in users
    }
    pending: dict[concurrent.futures.Future[dict[str, Any]], UserSpec] = {}
    sequence = 0
    page = 0
    next_stats = started
    stop = False
    while (time.monotonic() < deadline and not stop) or pending:
        now = time.monotonic()
        if now < deadline and not stop:
            for user in users:
                if now < due[user.label]:
                    continue
                due[user.label] = now + user.interval
                if metrics.mark_sent(user.label):
                    sequence += 1
                    pending[executor.submit(request_once, user, args, sequence)] = user
                else:
                    event = scheduler_drop(user)
                    metrics.record(event)
                    write_event(stream, event)
        for future in [item for item in pending if item.done()]:
            user = pending.pop(future)
            event = future.result()
            metrics.record(event)
            write_event(stream, event)
        if stdscr is not None:
            page = draw_dashboard(stdscr, metrics, started, page, args.page_size, matrix_line)
            stop = page < 0
        elif now >= next_stats:
            print_summary(metrics)
            next_stats = now + args.stats_interval
        time.sleep(0.02)
    for future, user in list(pending.items()):
        event = future.result()
        metrics.record(event)
        write_event(stream, event)


def run_traffic(args: argparse.Namespace, plan: dict[str, Any], key_path: Path) -> int:
    key = key_path.read_text(encoding="utf-8").strip()
    benchmark_lane = Lane("benchmark", "anthropic", args.model, plan["benchmark_url"], "/v1/messages")
    glm_lane = Lane("real-glm", "anthropic", args.glm_model, plan["gateway_url"], "/v1/messages")
    users = [
        UserSpec(f"shadow-user-{index:03d}", key, benchmark_lane, args.interval)
        for index in range(1, args.user_count + 1)
    ]
    users.append(UserSpec("real-glm", key, glm_lane, args.glm_interval))
    metrics = Metrics(users, args.window_seconds)
    evidence = Path(args.evidence).expanduser()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(args.concurrency, len(users)))
    started = time.monotonic()
    deadline = started + args.duration
    use_ui = args.ui == "always" or (args.ui == "auto" and sys.stdout.isatty() and sys.stdin.isatty())
    start_event = {
        "event": "run_start",
        "at": now_utc(),
        "phase": args.phase,
        "gateway_url_host": urlsplit(plan["gateway_url"]).hostname,
        "benchmark_url_host": urlsplit(plan["benchmark_url"]).hostname,
        "route_name": args.route_name,
        "users": args.user_count,
        "real_glm_users": 1,
        "real_glm_users": 1,
        "lanes": [
            {"lane": benchmark_lane.name, "provider": benchmark_lane.provider, "model": benchmark_lane.model, "base_url_host": urlsplit(benchmark_lane.base_url).hostname},
            {"lane": glm_lane.name, "provider": glm_lane.provider, "model": glm_lane.model, "base_url_host": urlsplit(glm_lane.base_url).hostname},
        ],
        "backend_marker_headers": args.marker_headers,
        "retries": 0,
        "real_matrix": args.real_matrix,
    }
    try:
        with evidence.open("w", encoding="utf-8") as stream:
            write_event(stream, start_event)
            matrix_line = run_matrix(args, plan, users[0].key, stream) if args.real_matrix else ""
            if use_ui:
                curses.wrapper(lambda stdscr: run_loop(stdscr, args, users, metrics, executor, stream, started, deadline, matrix_line))
            else:
                run_loop(None, args, users, metrics, executor, stream, started, deadline, matrix_line)
            overall, _ = metrics.snapshot()
            write_event(stream, {"event": "run_end", "at": now_utc(), **overall})
    finally:
        executor.shutdown(wait=True)
    print(f"evidence={evidence}")
    return 0


def dry_run_plan(args: argparse.Namespace, plan: dict[str, Any], key_path: Path) -> dict[str, Any]:
    return {
        "status": "dry-run-ready",
        "network": "disabled",
        "cluster_mutation": "disabled",
        "phase": args.phase,
        "oc_preflight": "read-only PriceTag checks completed",
        "namespace": args.namespace,
        "gateway_url_host": urlsplit(plan["gateway_url"]).hostname,
        "benchmark_url_host": urlsplit(plan["benchmark_url"]).hostname,
        "route_name": args.route_name,
        "shadow_route_checked": args.phase == "canary",
        "users": args.user_count,
        "key_file": str(key_path),
        "lanes": [
            {"lane": "benchmark", "provider": "anthropic", "model": args.model, "interval": args.interval},
            {"lane": "real-glm", "provider": "anthropic", "model": args.glm_model, "interval": args.glm_interval},
        ],
        "retries": 0,
        "real_matrix": args.real_matrix,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="PriceTag-only Praxis upgrade traffic watcher")
    result.add_argument("--phase", choices=("baseline", "canary"), default="baseline")
    result.add_argument("--oc-context", default=DEFAULT_CONTEXT)
    result.add_argument("--oc-server", default=DEFAULT_SERVER)
    result.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    result.add_argument("--route-name", default=DEFAULT_ROUTE)
    result.add_argument("--shadow-route-name", default=DEFAULT_SHADOW_ROUTE)
    result.add_argument("--gateway-url", help="override the normal PriceTag gateway URL")
    result.add_argument("--gateway-route-name", default="ai-gateway")
    result.add_argument("--model", default=DEFAULT_MODEL)
    result.add_argument("--glm-model", default="rits/zai-org/glm-5-3")
    result.add_argument("--glm-interval", type=float, default=30.0, help="seconds between real GLM calls")
    result.add_argument("--real-matrix", action="store_true", help="run one small four-route real-provider/local matrix before the load")
    result.add_argument("--messages-model", default="claude-sonnet-5")
    result.add_argument("--chat-model", default="gpt-5.6-luna")
    result.add_argument("--responses-model", default="gpt-5.3-codex")
    result.add_argument("--key-file", default="~/.mykey")
    result.add_argument("--user-count", type=int, default=96)
    result.add_argument("--interval", type=float, default=5.0)
    result.add_argument("--timeout", type=float, default=20.0)
    result.add_argument("--duration", type=float, default=300.0)
    result.add_argument("--concurrency", type=int, default=32)
    result.add_argument("--stats-interval", type=float, default=5.0)
    result.add_argument("--window-seconds", type=float, default=60.0)
    result.add_argument("--marker-headers", type=lambda value: [item.strip() for item in value.split(",") if item.strip()], default=["x-praxis-lane", "x-gateway-build"])
    result.add_argument("--evidence", default=f"/tmp/praxis-shadow-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl")
    result.add_argument("--ui", choices=("auto", "always", "never"), default="auto")
    result.add_argument("--page-size", type=int, default=0)
    result.add_argument("--dry-run", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if not 1 <= args.user_count <= MAX_USERS:
            raise ConfigError(f"--user-count must be between 1 and {MAX_USERS}")
        if args.duration <= 0 or args.interval <= 0 or args.glm_interval <= 0 or args.timeout <= 0 or args.concurrency <= 0:
            raise ConfigError("duration, interval, timeout, and concurrency must be positive")
        if args.real_matrix and args.phase != "canary":
            raise ConfigError("--real-matrix is only allowed in canary phase")
        args.oc_server = safe_url("PriceTag server", args.oc_server)
        reject_enmaas("PriceTag context", args.oc_context)
        reject_enmaas("PriceTag namespace", args.namespace)
        key_path = ensure_key(args)
        plan = prepare(args)
        if args.dry_run:
            print(json.dumps(dry_run_plan(args, plan, key_path), indent=2, sort_keys=True))
            return 0
        return run_traffic(args, plan, key_path)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
