#!/usr/bin/env python3
"""PriceTag-only Praxis shadow traffic watcher.

The default mode is intentionally read-only preflight.  Traffic mode requires
explicit PriceTag OpenShift coordinates, validates them with read-only ``oc``
commands, and sends one request at a time per logical user with no retries.

This tool never writes to OpenShift.  It never logs credentials, prompts, or
response bodies.  The request body is a fixed echo probe, and evidence contains
only safe metadata, status codes, timings, and error classes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import curses
import hashlib
import json
import math
import os
import re
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
FORBIDDEN_MARKER = "enmaas"
DEFAULT_OC_CONTEXT = "ai-gateway-dogfood/c117-e-us-south-containers-cloud-ibm-com:30087/IAM#yovadia@redhat.com"
DEFAULT_OC_SERVER = "https://c117-e.us-south.containers.cloud.ibm.com:30087"
DEFAULT_NAMESPACE = "ai-gateway-dogfood"
DEFAULT_BENCHMARK_URL = "https://ai-gateway-benchmark-shadow-ai-gateway-dogfood.dogfood-us-south-1-bxf-4x-f196230f74f7ff44a5b4eeb1003c5bd5-0000.us-south.containers.appdomain.cloud"
DEFAULT_GLM_MODEL = "rits/zai-org/glm-5-3"


class ConfigError(ValueError):
    """A safe, user-actionable configuration error."""


@dataclass(frozen=True)
class Lane:
    name: str
    provider: str
    model: str
    base_url: str
    path: str
    protocol: str
    source: str


@dataclass(frozen=True)
class UserSpec:
    label: str
    key: str
    lane: Lane


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def reject_forbidden(field: str, value: str) -> None:
    compact = value.casefold().replace("-", "").replace("_", "")
    if FORBIDDEN_MARKER in compact:
        raise ConfigError(f"{field} contains a forbidden EnMaaS marker")


def https_url(field: str, value: str) -> str:
    value = value.strip().rstrip("/")
    reject_forbidden(field, value)
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError(f"{field} must be an https URL with a hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{field} must not contain credentials, query, or fragment data")
    return value


def endpoint_url(field: str, value: str) -> str:
    """Validate an external HTTPS route or the explicit local port-forward."""
    value = value.strip().rstrip("/")
    reject_forbidden(field, value)
    parsed = urlsplit(value)
    if parsed.scheme == "https" and parsed.hostname:
        allowed = True
    elif parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        allowed = True
    else:
        allowed = False
    if not allowed:
        raise ConfigError(f"{field} must be an https URL, or http://localhost for the explicit port-forward")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{field} must not contain credentials, query, or fragment data")
    return value


def validate_args(args: argparse.Namespace) -> None:
    reject_forbidden("OpenShift context", args.oc_context)
    args.oc_server = https_url("OpenShift server", args.oc_server)
    reject_forbidden("PriceTag namespace", args.namespace)
    if not args.namespace.strip():
        raise ConfigError("--namespace is required")
    if not 1 <= args.user_count <= MAX_USERS:
        raise ConfigError(f"--user-count must be between 1 and {MAX_USERS}")
    if args.interval <= 0:
        raise ConfigError("--interval must be greater than zero")
    if args.timeout <= 0:
        raise ConfigError("--timeout must be greater than zero")
    if args.concurrency <= 0:
        raise ConfigError("--concurrency must be greater than zero")
    if args.stats_interval <= 0:
        raise ConfigError("--stats-interval must be greater than zero")
    if args.window_seconds <= 0:
        raise ConfigError("--window-seconds must be greater than zero")
    if args.duration < 0:
        raise ConfigError("--duration cannot be negative")
    if args.users_file:
        path = Path(args.users_file).expanduser()
        if not path.is_file():
            raise ConfigError("--users-file does not exist")
        args.users_file = str(path)


def build_lanes(args: argparse.Namespace, discovery: dict[str, Any]) -> tuple[Lane, Lane, Lane]:
    echo_model = args.echo_model or discovery["model"]
    return (
        Lane(
            name="openai-echo",
            provider="openai",
            model=echo_model,
            base_url=endpoint_url("OpenAI echo URL", args.openai_echo_url or "http://127.0.0.1:18087"),
            path="/v1/chat/completions",
            protocol="openai-chat-completions",
            source="praxis-ai-shadow-openai-echo",
        ),
        Lane(
            name="benchmark-echo",
            provider="anthropic",
            model=echo_model,
            base_url=endpoint_url("Benchmark echo URL", args.benchmark_url or discovery["benchmark_url"]),
            path="/v1/messages",
            protocol="anthropic-messages",
            source="praxis-ai-shadow-benchmark",
        ),
        Lane(
            name="glm-echo",
            provider="anthropic",
            model=args.glm_model or discovery["glm_model"],
            base_url=endpoint_url("GLM echo URL", args.glm_echo_url or "http://127.0.0.1:18086"),
            path="/v1/messages",
            protocol="anthropic-messages",
            source="praxis-ai-shadow-glm-echo",
        ),
    )


def ensure_key_file(args: argparse.Namespace) -> Path:
    path = Path(args.key_file).expanduser()
    if not path.is_file():
        raise ConfigError(f"PriceTag key file not found: {path}; create ~/.mykey or override --key-file")
    try:
        key = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"cannot read PriceTag key file: {path}") from exc
    if not key:
        raise ConfigError(f"PriceTag key file is empty: {path}")
    return path


def load_user_specs(args: argparse.Namespace, lanes: tuple[Lane, ...], key_path: Path) -> tuple[list[UserSpec], str]:
    shared_key = key_path.read_text(encoding="utf-8").strip()
    keys: list[str] = []
    source = f"key_file:{key_path}"

    if args.users_file:
        try:
            raw = json.loads(Path(args.users_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError("could not read --users-file") from exc
        entries = raw.get("users") if isinstance(raw, dict) else raw
        if not isinstance(entries, list) or len(entries) < args.user_count:
            raise ConfigError("--users-file does not contain enough users")
        source = "users-file"
        for entry in entries[: args.user_count]:
            if not isinstance(entry, dict):
                raise ConfigError("each users-file entry must be an object")
            key = entry.get("key") or entry.get("api_key") or shared_key
            if not isinstance(key, str) or not key:
                raise ConfigError("each users-file entry needs a key or the API-key environment variable")
            keys.append(key)
    else:
        keys = [shared_key] * args.user_count

    users: list[UserSpec] = []
    for index, key in enumerate(keys, start=1):
        label = f"shadow-user-{index:03d}"
        digest = hashlib.sha256(label.encode("utf-8")).digest()
        lane = lanes[digest[0] % len(lanes)]
        users.append(UserSpec(label=label, key=key, lane=lane))
    return users, source


def oc_run(args: argparse.Namespace, command: list[str]) -> str:
    if shutil.which("oc") is None:
        raise ConfigError("oc was not found in PATH")
    full = ["oc", "--context", args.oc_context, "--server", args.oc_server, *command]
    try:
        completed = subprocess.run(
            full,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ConfigError("read-only oc preflight timed out") from exc
    if completed.returncode != 0:
        raise ConfigError("read-only oc preflight failed")
    return completed.stdout.strip()


def validate_price_tag_oc(args: argparse.Namespace) -> None:
    try:
        observed_server = oc_run(args, ["whoami", "--show-server"]).rstrip("/")
        if observed_server != args.oc_server:
            raise ConfigError("oc reported a different server than --oc-server")
        oc_run(args, ["get", "namespace", args.namespace, "-o", "name"])
    except ConfigError as exc:
        raise ConfigError(
            "PriceTag oc login/namespace check failed; log in to the PriceTag OpenShift context "
            f"{args.oc_context!r} and ensure namespace {args.namespace!r} is accessible"
        ) from exc


def discover_environment(args: argparse.Namespace) -> dict[str, Any]:
    validate_price_tag_oc(args)
    try:
        raw = json.loads(oc_run(args, ["get", "deployment", "llm-katan", "-o", "json"]))
        container = raw["spec"]["template"]["spec"]["containers"][0]
        command_args = container.get("args", [])
    except (ConfigError, KeyError, IndexError, json.JSONDecodeError) as exc:
        raise ConfigError("llm-katan deployment was not found in the PriceTag namespace") from exc
    model = next((value.split("=", 1)[1] for value in command_args if value.startswith("--model=")), "benchmark-echo")
    providers_raw = next((value.split("=", 1)[1] for value in command_args if value.startswith("--providers=")), "openai,anthropic")
    providers = [item.strip() for item in providers_raw.split(",") if item.strip()]
    if not {"openai", "anthropic"}.issubset(providers):
        raise ConfigError(f"llm-katan echo deployment does not expose both OpenAI and Anthropic providers: {providers_raw}")
    try:
        oc_run(args, ["get", "service", "praxis-shadow", "-o", "name"])
    except ConfigError as exc:
        raise ConfigError("praxis-shadow service was not found in the PriceTag namespace") from exc
    benchmark_url = args.benchmark_url or DEFAULT_BENCHMARK_URL
    if not args.benchmark_url:
        try:
            host = oc_run(args, ["get", "route", "ai-gateway-benchmark-shadow", "-o", "jsonpath={.spec.host}"])
            if host:
                benchmark_url = f"https://{host}"
        except ConfigError:
            pass
    glm_model = DEFAULT_GLM_MODEL
    try:
        config = oc_run(args, ["get", "configmap", "praxis-shadow-config", "-o", "jsonpath={.data.praxis\\.yaml}"])
        glm_chain = re.search(r"(?ms)^  - name: glm-echo\n(?P<body>.*?)(?=^  - name: |\Z)", config)
        if glm_chain:
            model_match = re.search(r'default_model:\s*["\']([^"\']+)', glm_chain.group("body"))
            if model_match:
                glm_model = model_match.group(1)
    except ConfigError:
        pass
    return {"model": model, "providers": providers, "benchmark_url": benchmark_url, "glm_model": glm_model}


def wait_for_port(host: str, port: int, timeout: float) -> None:
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.2)
    raise ConfigError(f"local port-forward {host}:{port} did not become ready")


def start_port_forwards(args: argparse.Namespace) -> list[subprocess.Popen[str]]:
    processes: list[subprocess.Popen[str]] = []
    for local, remote, override in ((18087, 8087, args.openai_echo_url), (18086, 8086, args.glm_echo_url)):
        if override:
            continue
        process = subprocess.Popen(
            [
                "oc", "--context", args.oc_context, "--server", args.oc_server,
                "-n", args.namespace, "port-forward", "svc/praxis-shadow", f"{local}:{remote}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        processes.append(process)
        try:
            wait_for_port("127.0.0.1", local, 15)
        except ConfigError:
            stop_port_forwards(processes)
            raise
    return processes


def stop_port_forwards(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


class Metrics:
    def __init__(self, users: list[UserSpec], window_seconds: float) -> None:
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.window_seconds = window_seconds
        self.users = {
            user.label: {
                "user": user.label,
                "lane": user.lane.name,
                "provider": user.lane.provider,
                "model": user.lane.model,
                "sent": 0,
                "responses": 0,
                "drops": 0,
                "in_flight": False,
                "last": "never",
                "last_status": None,
                "last_latency_ms": None,
                "samples": deque(maxlen=4000),
            }
            for user in users
        }
        self.statuses: Counter[str] = Counter()
        self.lane_events: dict[str, dict[str, Any]] = {
            user.lane.name: {
                "lane": user.lane.name,
                "provider": user.lane.provider,
                "model": user.lane.model,
                "sent": 0,
                "responses": 0,
                "drops": 0,
                "samples": deque(maxlen=10000),
            }
            for user in users
        }

    def mark_sent(self, label: str) -> bool:
        with self.lock:
            row = self.users[label]
            if row["in_flight"]:
                return False
            row["in_flight"] = True
            row["sent"] += 1
            self.lane_events[row["lane"]]["sent"] += 1
            return True

    def record(self, event: dict[str, Any]) -> None:
        with self.lock:
            row = self.users[event["user"]]
            lane = self.lane_events[event["lane"]]
            row["in_flight"] = False
            row["last"] = event["outcome"] if event["outcome"] == "drop" else f"http_{event['status']}"
            row["last_status"] = event["status"]
            row["last_latency_ms"] = event["latency_ms"]
            row["samples"].append((time.monotonic(), event["latency_ms"]))
            lane["samples"].append((time.monotonic(), event["latency_ms"]))
            if event["outcome"] == "drop":
                row["drops"] += 1
                lane["drops"] += 1
            else:
                row["responses"] += 1
                lane["responses"] += 1
                self.statuses[str(event["status"])] += 1

    def snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self.lock:
            overall_samples: list[float] = []
            users: list[dict[str, Any]] = []
            lanes: list[dict[str, Any]] = []
            for row in self.users.values():
                while row["samples"] and row["samples"][0][0] < cutoff:
                    row["samples"].popleft()
                samples = [value for _, value in row["samples"]]
                overall_samples.extend(samples)
                users.append({
                    key: value
                    for key, value in row.items()
                    if key != "samples"
                } | {"p50_ms": percentile(samples, 0.50), "p95_ms": percentile(samples, 0.95), "p99_ms": percentile(samples, 0.99)})
            for row in self.lane_events.values():
                while row["samples"] and row["samples"][0][0] < cutoff:
                    row["samples"].popleft()
                samples = [value for _, value in row["samples"]]
                lanes.append({
                    key: value
                    for key, value in row.items()
                    if key != "samples"
                } | {"p50_ms": percentile(samples, 0.50), "p95_ms": percentile(samples, 0.95), "p99_ms": percentile(samples, 0.99)})
            sent = sum(row["sent"] for row in self.users.values())
            responses = sum(row["responses"] for row in self.users.values())
            drops = sum(row["drops"] for row in self.users.values())
            in_flight = sum(1 for row in self.users.values() if row["in_flight"])
            overall = {
                "sent": sent,
                "responses": responses,
                "drops": drops,
                "in_flight": in_flight,
                "status_codes": dict(sorted(self.statuses.items())),
                "p50_ms": percentile(overall_samples, 0.50),
                "p95_ms": percentile(overall_samples, 0.95),
                "p99_ms": percentile(overall_samples, 0.99),
            }
            return overall, users, lanes


def discard_body(stream: Any) -> None:
    while stream.read(8192):
        pass


def request_once(user: UserSpec, sequence: int, timeout: float) -> dict[str, Any]:
    lane = user.lane
    if lane.protocol == "openai-chat-completions":
        body = {
            "model": lane.model,
            "messages": [{"role": "user", "content": "echo"}],
            "max_tokens": 1,
        }
        auth = {"Authorization": f"Bearer {user.key}"}
    else:
        body = {
            "model": lane.model,
            "messages": [{"role": "user", "content": "echo"}],
            "max_tokens": 1,
        }
        auth = {
            "x-api-key": user.key,
            "anthropic-version": "2023-06-01",
        }
    request = urllib.request.Request(
        lane.base_url + lane.path,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "praxis-ai-shadow-traffic/1",
            "X-Request-ID": f"praxis-shadow-{user.label}-{sequence}",
            **auth,
        },
    )
    started = time.monotonic()
    event: dict[str, Any] = {
        "event": "request_result",
        "at": utc_now(),
        "user": user.label,
        "lane": lane.name,
        "provider": lane.provider,
        "model": lane.model,
        "status": None,
        "outcome": "drop",
        "error_class": None,
        "latency_ms": 0.0,
    }
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            discard_body(response)
            event["status"] = response.status
            event["outcome"] = "response"
            if response.status < 200 or response.status >= 300:
                event["error_class"] = f"http_{response.status}"
    except urllib.error.HTTPError as exc:
        discard_body(exc)
        event["status"] = exc.code
        event["outcome"] = "response"
        event["error_class"] = f"http_{exc.code}"
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
        "event": "scheduler_drop",
        "at": utc_now(),
        "user": user.label,
        "lane": user.lane.name,
        "provider": user.lane.provider,
        "model": user.lane.model,
        "status": None,
        "outcome": "drop",
        "error_class": "in_flight",
        "latency_ms": 0.0,
    }


def write_event(stream: Any, event: dict[str, Any]) -> None:
    stream.write(json.dumps(event, sort_keys=True) + "\n")
    stream.flush()


def draw_dashboard(stdscr: Any, metrics: Metrics, started: float, page: int, page_size: int) -> int:
    stdscr.erase()
    stdscr.timeout(200)
    overall, users, lanes = metrics.snapshot()
    height, width = stdscr.getmaxyx()
    lines = [
        "PRAXIS SHADOW TRAFFIC — PriceTag / llm-katan echo only",
        f"elapsed {time.monotonic() - started:7.1f}s  sent {overall['sent']:,}  responses {overall['responses']:,}  drops {overall['drops']:,}  in-flight {overall['in_flight']}",
        f"latency p50/p95/p99 {overall['p50_ms']:.0f}/{overall['p95_ms']:.0f}/{overall['p99_ms']:.0f} ms  status {overall['status_codes']}",
    ]
    for lane in lanes:
        lines.append(f"{lane['lane']:<18} {lane['provider']:<10} {lane['model']:<20} sent={lane['sent']:<6} responses={lane['responses']:<6} drops={lane['drops']:<6} p95={lane['p95_ms']:.0f}ms")
    lines.append("─" * max(1, width - 1))
    lines.append("USER             LANE              SENT RESP DROP LAST             LATENCY")
    usable = max(1, height - len(lines) - 2)
    visible = min(page_size if page_size > 0 else usable, usable)
    pages = max(1, math.ceil(len(users) / visible))
    page = page % pages
    for row in users[page * visible : (page + 1) * visible]:
        lines.append(
            f"{row['user']:<17.17} {row['lane']:<18.18} {row['sent']:>4} {row['responses']:>4} {row['drops']:>4} "
            f"{str(row['last']):<17.17} {str(row['last_latency_ms'] or 0):>7}ms"
        )
    lines.append(f"page {page + 1}/{pages}  ←/→ page  q quit")
    for index, line in enumerate(lines[:height]):
        try:
            stdscr.addnstr(index, 0, line, max(0, width - 1))
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
    overall, _, lanes = metrics.snapshot()
    lane_summary = " ".join(
        f"{lane['lane']}={lane['responses']}r/{lane['drops']}d/p95:{lane['p95_ms']:.0f}ms"
        for lane in lanes
    )
    print(
        f"sent={overall['sent']} responses={overall['responses']} drops={overall['drops']} "
        f"p50/p95/p99={overall['p50_ms']:.0f}/{overall['p95_ms']:.0f}/{overall['p99_ms']:.0f}ms "
        f"status={overall['status_codes']} {lane_summary}",
        flush=True,
    )


def traffic_loop(
    stdscr: Any,
    args: argparse.Namespace,
    users: list[UserSpec],
    metrics: Metrics,
    executor: concurrent.futures.ThreadPoolExecutor,
    stream: Any,
    started: float,
    deadline: float,
) -> None:
    next_due = {
        user.label: started + (int.from_bytes(hashlib.sha256(user.label.encode()).digest()[:4], "big") / 2**32) * args.interval
        for user in users
    }
    pending: dict[concurrent.futures.Future[dict[str, Any]], UserSpec] = {}
    sequence = 0
    page = 0
    next_stats = started
    stop_requested = False
    while (time.monotonic() < deadline and not stop_requested) or pending:
        now = time.monotonic()
        if now < deadline and not stop_requested:
            for user in users:
                if now < next_due[user.label]:
                    continue
                next_due[user.label] = now + args.interval
                if metrics.mark_sent(user.label):
                    sequence += 1
                    pending[executor.submit(request_once, user, sequence, args.timeout)] = user
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
            page = draw_dashboard(stdscr, metrics, started, page, args.page_size)
            if page < 0:
                stop_requested = True
        elif now >= next_stats:
            print_summary(metrics)
            next_stats = now + args.stats_interval
        time.sleep(0.02)
    for future, user in list(pending.items()):
        event = future.result()
        metrics.record(event)
        write_event(stream, event)


def run_traffic(
    args: argparse.Namespace,
    lanes: tuple[Lane, ...],
    users: list[UserSpec],
    credential_source: str,
    discovery: dict[str, Any],
) -> int:
    forwards = start_port_forwards(args)
    evidence = Path(args.evidence).expanduser()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    metrics = Metrics(users, args.window_seconds)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(args.concurrency, len(users)))
    started = time.monotonic()
    deadline = started + args.duration if args.duration else float("inf")
    plan = {
        "event": "run_start",
        "at": utc_now(),
        "oc_context": args.oc_context,
        "oc_server_host": urlsplit(args.oc_server).hostname,
        "namespace": args.namespace,
        "users": len(users),
        "credential_source": credential_source,
        "llm_katan": {"providers": discovery["providers"], "model": discovery["model"], "glm_model": discovery["glm_model"]},
        "lanes": [
            {"lane": lane.name, "provider": lane.provider, "model": lane.model, "protocol": lane.protocol, "source": lane.source}
            for lane in lanes
        ],
        "retries": 0,
    }
    use_ui = args.ui == "always" or (args.ui == "auto" and sys.stdout.isatty() and sys.stdin.isatty())
    try:
        with evidence.open("w", encoding="utf-8") as stream:
            write_event(stream, plan)
            if use_ui:
                curses.wrapper(lambda stdscr: traffic_loop(stdscr, args, users, metrics, executor, stream, started, deadline))
            else:
                traffic_loop(None, args, users, metrics, executor, stream, started, deadline)
            overall, _, _ = metrics.snapshot()
            write_event(stream, {"event": "run_end", "at": utc_now(), **overall})
    finally:
        executor.shutdown(wait=True)
        stop_port_forwards(forwards)
    print(f"evidence={evidence}")
    return 0


def dry_run_plan(
    args: argparse.Namespace,
    lanes: tuple[Lane, ...],
    users: list[UserSpec],
    credential_source: str,
    discovery: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": "dry-run-ready",
        "network": "disabled",
        "cluster_mutation": "disabled",
        "oc_preflight": "read-only PriceTag check completed",
        "oc_context": args.oc_context,
        "oc_server_host": urlsplit(args.oc_server).hostname,
        "namespace": args.namespace,
        "users": len(users),
        "credential_source": credential_source,
        "llm_katan": {"providers": discovery["providers"], "model": discovery["model"], "glm_model": discovery["glm_model"]},
        "retries": 0,
        "evidence": str(Path(args.evidence).expanduser()),
        "lanes": [
            {"lane": lane.name, "provider": lane.provider, "model": lane.model, "protocol": lane.protocol, "source": lane.source}
            for lane in lanes
        ],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="PriceTag-only Praxis shadow traffic watcher")
    result.add_argument("--oc-context", default=DEFAULT_OC_CONTEXT, help="override the PriceTag OpenShift context")
    result.add_argument("--oc-server", default=DEFAULT_OC_SERVER, help="override the PriceTag OpenShift API server")
    result.add_argument("--namespace", default=DEFAULT_NAMESPACE, help="override the PriceTag namespace")
    result.add_argument("--openai-echo-url", help="override OpenAI echo endpoint; default: auto port-forward")
    result.add_argument("--glm-echo-url", help="override GLM echo endpoint; default: auto port-forward")
    result.add_argument("--benchmark-url", help="override Benchmark echo route")
    result.add_argument("--echo-model", help="override llm-katan's discovered echo model")
    result.add_argument("--glm-model", help="override the discovered GLM echo model")
    result.add_argument("--key-file", default="~/.mykey", help="PriceTag key file")
    result.add_argument("--users-file", help="optional JSON inventory containing per-user keys")
    result.add_argument("--user-count", type=int, default=100)
    result.add_argument("--interval", type=float, default=5.0, help="seconds between attempts per user")
    result.add_argument("--timeout", type=float, default=20.0)
    result.add_argument("--duration", type=float, default=300.0, help="seconds; default five minutes")
    result.add_argument("--concurrency", type=int, default=32)
    result.add_argument("--stats-interval", type=float, default=5.0)
    result.add_argument("--window-seconds", type=float, default=60.0)
    result.add_argument("--evidence", default=f"/tmp/praxis-shadow-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl")
    result.add_argument("--ui", choices=("auto", "always", "never"), default="auto")
    result.add_argument("--page-size", type=int, default=0)
    result.add_argument("--dry-run", action="store_true", help="validate configuration only; no oc or HTTP calls")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        validate_args(args)
        key_path = ensure_key_file(args)
        discovery = discover_environment(args)
        lanes = build_lanes(args, discovery)
        users, credential_source = load_user_specs(args, lanes, key_path)
        if args.dry_run:
            print(json.dumps(dry_run_plan(args, lanes, users, credential_source, discovery), indent=2, sort_keys=True))
            return 0
        return run_traffic(args, lanes, users, credential_source, discovery)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
