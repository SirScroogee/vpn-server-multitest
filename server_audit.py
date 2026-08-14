#!/usr/bin/env python3
"""Standalone server suitability audit for VPN and general network traffic.

The script intentionally uses only the Python standard library.  External Linux
utilities are detected at runtime and missing tests are reported as skipped.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import glob
import ipaddress
import json
import locale
import math
import os
import pathlib
import platform
import re
import shlex
import shutil
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


VERSION = "1.17.1"
DEFAULT_TARGETS = ["1.1.1.1", "dns.google"]
DEFAULT_REPORT_DIR = "server-audit-reports"
IPERF_TCP_STREAM_PROFILES = (1, 4)
DEFAULT_MTR_COUNT = 30
RU_IPERF_CATALOG_URL = (
    "https://raw.githubusercontent.com/itdoginfo/russian-iperf3-servers/main/list.yml"
)
RU_IPERF_CATALOG_SOURCE = "https://github.com/itdoginfo/russian-iperf3-servers"
TARGET_TESTS = {"ping", "tcp", "mtr", "traceroute", "pmtu", "soak"}
COUNTRY_NAMES_RU = {
    "DE": "Германия",
    "FI": "Финляндия",
    "FR": "Франция",
    "GB": "Великобритания",
    "KZ": "Казахстан",
    "LT": "Литва",
    "LV": "Латвия",
    "NL": "Нидерланды",
    "PL": "Польша",
    "RU": "Россия",
    "SE": "Швеция",
    "TR": "Турция",
    "US": "США",
}
TEST_ALIASES = {
    "ping": {"ping"},
    "mtr": {"mtr"},
    "trace": {"traceroute"},
    "traceroute": {"traceroute"},
    "iperf": {"iperf"},
    "udp": {"udp"},
    "soak": {"soak"},
    "long": {"soak"},
    "pmtu": {"pmtu"},
    "system": {"system"},
    "disk": {"disk"},
    "tcp": {"tcp"},
    "dns": {"dnscheck"},
    "dnscheck": {"dnscheck"},
    "ip": {"ipinfo"},
    "geo": {"ipinfo"},
    "ipinfo": {"ipinfo"},
    "access": {"access"},
    "dpi": {"dpi"},
    "censor": {"access", "dpi", "dnscheck"},
    "quick": {"system", "ping", "tcp", "ipinfo", "dnscheck"},
    "network": {"ping", "tcp", "mtr", "traceroute", "dnscheck"},
    "full": {
        "system",
        "ping",
        "tcp",
        "mtr",
        "traceroute",
        "iperf",
        "udp",
        "ipinfo",
        "access",
        "dpi",
        "dnscheck",
        "disk",
    },
}

IPERF_PROFILES = {
    "ru-core": ["Moscow", "Saint Petersburg", "Yekaterinburg", "Novosibirsk", "Krasnodar"],
    "ru-west": ["Moscow", "Saint Petersburg", "Nizhny Novgorod", "Rostov-on-Don", "Krasnodar"],
    "ru-ural-volga": ["Yekaterinburg", "Kazan", "Samara", "Ufa", "Tyumen"],
    "ru-siberia-east": ["Novosibirsk", "Krasnoyarsk", "Irkutsk", "Omsk", "Yakutsk"],
}

# Offline fallback.  The live catalog above is preferred and currently checked
# every day by its maintainers.  These entries deliberately span multiple
# operators and Russian regions.
BUILTIN_RU_IPERF = [
    ("Hostkey Moscow", "Moscow", "spd-rudp.hostkey.ru", "5201-5209"),
    ("MTS Moscow", "Moscow", "mskst.st.mtsws.net", "3333"),
    ("Ertelecom Saint Petersburg", "Saint Petersburg", "st.spb.ertelecom.ru", "5201-5209"),
    ("Ertelecom Yekaterinburg", "Yekaterinburg", "st.ekat.ertelecom.ru", "5201-5209"),
    ("Ertelecom Kazan", "Kazan", "st.kzn.ertelecom.ru", "5201-5209"),
    ("Ertelecom Samara", "Samara", "st.samara.ertelecom.ru", "5201-5209"),
    ("Ertelecom Ufa", "Ufa", "st.ufa.ertelecom.ru", "5201-5209"),
    ("MTS Tyumen", "Tyumen", "tumst.st.mtsws.net", "3333"),
    ("Ertelecom Novosibirsk", "Novosibirsk", "st.nsk.ertelecom.ru", "5201-5209"),
    ("Ertelecom Krasnoyarsk", "Krasnoyarsk", "st.krsk.ertelecom.ru", "5201-5209"),
    ("Ertelecom Irkutsk", "Irkutsk", "st.irkutsk.ertelecom.ru", "5201-5209"),
    ("Ertelecom Omsk", "Omsk", "st.omsk.ertelecom.ru", "5201-5209"),
    ("MTS Krasnodar", "Krasnodar", "kndst.st.mtsws.net", "3333"),
    ("Ertelecom Rostov-on-Don", "Rostov-on-Don", "st.rostov.ertelecom.ru", "5201-5209"),
    ("MTS Yakutsk", "Yakutsk", "yktst.st.mtsws.net", "3333"),
    ("TTK Nizhny Novgorod", "Nizhny Novgorod", "speed-nn.vtt.net", "5201"),
]

ACCESS_TARGETS = [
    ("Google", "https://www.google.com/generate_204"),
    ("YouTube", "https://www.youtube.com/generate_204"),
    ("Google Play", "https://play.google.com/store"),
    ("Telegram API", "https://api.telegram.org"),
    ("GitHub", "https://github.com"),
    ("ChatGPT", "https://chatgpt.com"),
    ("Google Gemini", "https://gemini.google.com/app"),
    ("Google AI Studio", "https://aistudio.google.com"),
    ("Claude", "https://claude.ai"),
    ("Microsoft Copilot", "https://copilot.microsoft.com"),
    ("Discord", "https://discord.com"),
    ("Reddit", "https://www.reddit.com"),
    ("LinkedIn", "https://www.linkedin.com"),
    ("Spotify", "https://open.spotify.com"),
    ("Netflix", "https://www.netflix.com"),
    ("Patreon", "https://www.patreon.com"),
    ("DigitalOcean", "https://www.digitalocean.com"),
    ("Snyk", "https://snyk.io"),
    ("MongoDB", "https://www.mongodb.com"),
    ("Redis", "https://redis.io"),
    ("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
    ("Google DoH", "https://dns.google/resolve?name=example.com&type=A"),
    ("Cloudflare DoH", "https://cloudflare-dns.com/dns-query?name=example.com&type=A"),
]

# The list follows the useful, non-destructive part of vernette/censorcheck's
# Russian DPI profile.  Every target is requested over both HTTP and HTTPS;
# failures are only reported as *signs* of filtering, never as proof of DPI.
DPI_TARGETS = [
    ("YouTube", "youtube.com"),
    ("Google Video", "redirector.googlevideo.com/report_mapping?di=no"),
    ("Discord", "discord.com"),
    ("Instagram", "instagram.com"),
    ("Facebook", "facebook.com"),
    ("X / Twitter", "x.com"),
    ("LinkedIn", "linkedin.com"),
    ("Rutracker", "rutracker.org"),
    ("DigitalOcean", "digitalocean.com"),
    ("Amnezia", "amnezia.org"),
    ("Outline", "getoutline.org"),
    ("Mailfence", "mailfence.com"),
    ("Telegram API", "api.telegram.org"),
    ("Google Play", "play.google.com"),
]

DNS_RESOLVERS = [
    ("Cloudflare", "1.1.1.1", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare", "1.0.0.1", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
    ("Google", "8.8.8.8", "dns.google", "https://dns.google/dns-query"),
    ("Google", "8.8.4.4", "dns.google", "https://dns.google/dns-query"),
    ("Quad9", "9.9.9.9", "dns.quad9.net", "https://dns.quad9.net/dns-query"),
    ("Quad9", "9.9.9.10", "dns10.quad9.net", "https://dns10.quad9.net/dns-query"),
    ("Yandex", "77.88.8.8", "common.dot.dns.yandex.net", "https://common.dot.dns.yandex.net/dns-query"),
    ("Yandex", "77.88.8.1", "common.dot.dns.yandex.net", "https://common.dot.dns.yandex.net/dns-query"),
]


@dataclasses.dataclass
class TestResult:
    name: str
    category: str
    status: str
    summary: str
    command: str | None = None
    elapsed_seconds: float | None = None
    metrics: dict[str, Any] = dataclasses.field(default_factory=dict)
    output: str = ""

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class IperfEndpoint:
    name: str
    city: str
    host: str
    ports: tuple[int, ...] = (5201,)
    public: bool = True
    supports_udp: bool = False
    source: str = RU_IPERF_CATALOG_SOURCE

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AuditConfig:
    label: str
    targets: list[str]
    tests: set[str]
    # Kept only so older Python callers that passed role= keep working.  The
    # value no longer changes prompts, scoring or reports.
    role: str = "generic"
    iperf_host: str | None = None
    iperf_port: int = 5201
    iperf_endpoints: list[IperfEndpoint] = dataclasses.field(default_factory=list)
    iperf_catalog_mode: str | None = None
    iperf_seconds: int = 10
    # Used only by the optional long-running custom-server load test. The
    # regular TCP iperf3 test always runs both 1-stream and 4-stream profiles.
    iperf_streams: int = 4
    udp_mbps: int = 50
    # 0 enables the default automatic speed assessment. A positive value is a
    # user-supplied tariff/workload target kept for CLI and API compatibility.
    expected_mbps: int = 0
    output_dir: pathlib.Path = pathlib.Path(DEFAULT_REPORT_DIR)
    ping_count: int = 20
    tcp_port: int = 443
    soak_seconds: int = 300
    soak_interval_seconds: int = 15
    soak_iperf_host: str | None = None
    soak_iperf_port: int = 5201
    check_ip: str | None = None
    show_progress: bool = True
    color_output: bool = True
    clear_before_report: bool = False


def _format_duration(seconds: float | None) -> str:
    if seconds is None or not math.isfinite(seconds):
        return "--:--"
    value = max(0, int(round(seconds)))
    hours, remainder = divmod(value, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"


class ProgressTracker:
    """Dependency-free overall progress with a smoothly updated current stage."""

    FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(self, total_units: float, *, enabled: bool = True) -> None:
        self.total_units = max(float(total_units), 0.1)
        self.enabled = enabled
        self.dynamic = enabled and bool(getattr(sys.stdout, "isatty", lambda: False)())
        self.completed_units = 0.0
        self.started = time.monotonic()
        self.stage_started: float | None = None
        self.stage_units = 0.0
        self.stage_label = "Подготовка"
        self.detail_label = self.stage_label
        self.last_width = 0
        self.frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if self.dynamic:
            self._thread = threading.Thread(target=self._heartbeat, daemon=True)
            self._thread.start()

    def _heartbeat(self) -> None:
        while not self._stop.wait(0.2):
            self.render()

    def _snapshot(self) -> tuple[float, float | None, str, str]:
        with self._lock:
            elapsed = time.monotonic() - self.started
            active_elapsed = (
                time.monotonic() - self.stage_started if self.stage_started is not None else 0.0
            )
            active_fraction = (
                min(0.95, active_elapsed / max(self.stage_units, 0.1) * 0.9)
                if self.stage_started is not None
                else 0.0
            )
            progress_units = min(
                self.total_units,
                self.completed_units + self.stage_units * active_fraction,
            )
            percent = progress_units / self.total_units * 100
            observed_rate = self.completed_units / elapsed if self.completed_units > 0 and elapsed > 0 else 1.0
            remaining = max(0.0, self.total_units - progress_units)
            eta = remaining / max(observed_rate, 0.05)
            frame = self.FRAMES[self.frame % len(self.FRAMES)]
            self.frame += 1
            return percent, eta, self.detail_label, frame

    def _line(self, label: str | None = None, *, done: bool = False) -> str:
        percent, eta, current, frame = self._snapshot()
        if done:
            percent = min(100.0, self.completed_units / self.total_units * 100)
            eta = 0.0 if percent >= 99.95 else eta
            frame = "✓"
        width = 28
        filled = min(width, int(percent / 100 * width))
        bar = "█" * filled + "░" * (width - filled)
        text = label or current
        terminal_width = shutil.get_terminal_size((110, 24)).columns
        fixed = 49
        text = text[: max(12, terminal_width - fixed)]
        return f"[{bar}] {percent:6.1f}% | осталось ~{_format_duration(eta)} | {frame} {text}"

    def render(self) -> None:
        if not self.dynamic:
            return
        line = self._line()
        with self._lock:
            padding = " " * max(0, self.last_width - len(line))
            self.last_width = len(line)
            sys.stdout.write("\r" + line + padding)
            sys.stdout.flush()

    def begin(self, label: str, units: float) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.stage_label = label
            self.detail_label = label
            self.stage_units = max(float(units), 0.1)
            self.stage_started = time.monotonic()
        if self.dynamic:
            self.render()
        else:
            print(self._line())

    def detail(self, label: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.detail_label = label

    def finish(self, *, failed: bool = False) -> None:
        if not self.enabled:
            return
        with self._lock:
            label = self.stage_label
            self.completed_units = min(self.total_units, self.completed_units + self.stage_units)
            self.stage_started = None
            self.stage_units = 0.0
            self.detail_label = label
        line = self._line(label, done=True)
        if self.dynamic:
            with self._lock:
                padding = " " * max(0, self.last_width - len(line))
                self.last_width = 0
                sys.stdout.write("\r" + line + padding + "\n")
                sys.stdout.flush()
        else:
            print(line)

    def run(self, label: str, units: float, function: Any) -> Any:
        self.begin(label, units)
        try:
            result = function()
        except BaseException:
            self.finish(failed=True)
            raise
        self.finish()
        return result

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


_ACTIVE_PROGRESS: ProgressTracker | None = None


def _stage_output(message: str, detail: str | None = None) -> None:
    if _ACTIVE_PROGRESS:
        _ACTIVE_PROGRESS.detail(detail or message.lstrip("\n▶ "))
    if not _ACTIVE_PROGRESS or not _ACTIVE_PROGRESS.dynamic:
        print(message)


class CommandRunner:
    def __init__(self, verbose: bool = True, progress: ProgressTracker | None = None) -> None:
        self.verbose = verbose
        self.progress = progress

    def run(
        self,
        name: str,
        category: str,
        args: list[str],
        timeout: int,
        *,
        env: dict[str, str] | None = None,
    ) -> TestResult:
        command = shlex.join(args)
        if self.progress:
            self.progress.detail(name)
        show_raw = self.verbose and not (self.progress and self.progress.dynamic)
        if show_raw:
            print(f"\n▶ {name}\n  $ {command}")
        started = time.monotonic()
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                timeout=timeout,
                env=env,
                check=False,
            )
        except FileNotFoundError:
            return TestResult(
                name=name,
                category=category,
                status="skipped",
                summary=f"Команда {args[0]} не установлена",
                command=command,
            )
        except subprocess.TimeoutExpired as exc:
            output = _combine_output(exc.stdout or "", exc.stderr or "")
            return TestResult(
                name=name,
                category=category,
                status="failed",
                summary=f"Превышен тайм-аут {timeout} с",
                command=command,
                elapsed_seconds=round(time.monotonic() - started, 3),
                output=output,
            )

        output = _combine_output(completed.stdout, completed.stderr)
        elapsed = round(time.monotonic() - started, 3)
        if show_raw and output:
            print(output.rstrip())
        return TestResult(
            name=name,
            category=category,
            status="ok" if completed.returncode == 0 else "failed",
            summary="Выполнено" if completed.returncode == 0 else f"Код возврата {completed.returncode}",
            command=command,
            elapsed_seconds=elapsed,
            metrics={"return_code": completed.returncode},
            output=output,
        )


def _decode_process_output(value: str | bytes) -> str:
    if isinstance(value, str):
        return value
    encodings = ["utf-8"]
    if os.name == "nt":
        # Windows console utilities such as ping/tracert write redirected text
        # in the OEM code page (CP866 on a Russian system), not in the ANSI
        # code page returned by Python's default locale.
        encodings.extend(["oem", "cp866"])
    preferred = locale.getpreferredencoding(False)
    if preferred:
        encodings.append(preferred)
    for encoding in dict.fromkeys(encodings):
        try:
            return value.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode(encodings[0], errors="replace")


def _combine_output(stdout: str | bytes, stderr: str | bytes) -> str:
    stdout = _decode_process_output(stdout).replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    stderr = _decode_process_output(stderr).replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    parts = [part.strip() for part in (stdout, stderr) if part and part.strip()]
    return "\n".join(parts)


def safe_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return cleaned[:60] or "server"


def automatic_label(now: dt.datetime | None = None) -> str:
    """Return a compact label based on local wall-clock time."""
    return (now or dt.datetime.now()).strftime("audit_%d%m%y_%H%M")


def validate_host(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253 or any(char.isspace() for char in value):
        raise ValueError(f"Некорректная цель: {value!r}")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"Некорректное имя хоста: {value!r}")
    return value


def parse_host_port(value: str, default_port: int = 5201) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::(\d+))?", value)
        if not match:
            raise ValueError("IPv6 укажите как [2001:db8::1]:5201")
        host, port_text = match.groups()
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            host, port_text = value, None
    else:
        host, port_text = value, None
    host = validate_host(host)
    port = int(port_text) if port_text else default_port
    if not 1 <= port <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535")
    return host, port


def parse_port_spec(value: str | int) -> tuple[int, ...]:
    if isinstance(value, int):
        ports = [value]
    else:
        ports = []
        for part in str(value).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                start, end = int(start_text), int(end_text)
                ports.extend(range(min(start, end), max(start, end) + 1))
            else:
                ports.append(int(part))
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError(f"Некорректные порты: {value!r}")
    return tuple(dict.fromkeys(ports))


def parse_simple_iperf_catalog(content: str) -> list[IperfEndpoint]:
    """Parse the intentionally simple list.yml without requiring PyYAML."""
    endpoints: list[IperfEndpoint] = []
    current: dict[str, str] = {}

    def finish() -> None:
        if {"Name", "City", "address"} <= current.keys():
            try:
                endpoints.append(
                    IperfEndpoint(
                        name=current["Name"],
                        city=current["City"],
                        host=validate_host(current["address"]),
                        ports=parse_port_spec(current.get("port", "5201")),
                    )
                )
            except ValueError:
                pass

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            finish()
            current = {}
            line = line[2:].strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip().strip("'\"")
    finish()
    return endpoints


def builtin_ru_iperf_catalog() -> list[IperfEndpoint]:
    return [
        IperfEndpoint(name=name, city=city, host=host, ports=parse_port_spec(ports))
        for name, city, host, ports in BUILTIN_RU_IPERF
    ]


def _http_bytes(url: str, timeout: int = 8, max_bytes: int = 1_000_000) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"server-suitability-audit/{VERSION}",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(max_bytes + 1)[:max_bytes]


def _http_json(url: str, timeout: int = 8) -> dict[str, Any]:
    payload = json.loads(_http_bytes(url, timeout=timeout).decode("utf-8", errors="replace"))
    return payload if isinstance(payload, dict) else {}


def load_ru_iperf_catalog(online: bool = True) -> tuple[list[IperfEndpoint], str]:
    if online:
        try:
            content = _http_bytes(RU_IPERF_CATALOG_URL, timeout=8).decode("utf-8", errors="replace")
            endpoints = parse_simple_iperf_catalog(content)
            if len(endpoints) >= 10:
                return endpoints, "live"
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            pass
    return builtin_ru_iperf_catalog(), "builtin-fallback"


def filter_iperf_catalog(
    endpoints: list[IperfEndpoint], cities: list[str] | None = None
) -> list[IperfEndpoint]:
    if not cities:
        return endpoints
    wanted = {city.casefold() for city in cities}
    return [endpoint for endpoint in endpoints if endpoint.city.casefold() in wanted]


def find_open_port(host: str, ports: tuple[int, ...], timeout: float = 1.5) -> int | None:
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for port in ports:
        for family, socktype, protocol, _, sockaddr in addresses:
            target = (sockaddr[0], port, *sockaddr[2:])
            try:
                with socket.socket(family, socktype, protocol) as connection:
                    connection.settimeout(timeout)
                    if connection.connect_ex(target) == 0:
                        return port
            except OSError:
                continue
    return None


def find_working_iperf_port(host: str, ports: tuple[int, ...]) -> int | None:
    if shutil.which("iperf3") is None:
        return None
    for port in ports:
        if find_open_port(host, (port,), timeout=1.0) is None:
            continue
        try:
            completed = subprocess.run(
                ["iperf3", "-c", host, "-p", str(port), "-J", "-t", "1", "-P", "1"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=7,
                env=_base_environment(),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        metrics = parse_iperf_json(_combine_output(completed.stdout, completed.stderr))
        if completed.returncode == 0 and "mbps" in metrics:
            return port
    return None


def select_available_iperf_endpoints(
    endpoints: list[IperfEndpoint], limit: int | None = None
) -> tuple[list[tuple[IperfEndpoint, int]], list[IperfEndpoint]]:
    selected: list[tuple[IperfEndpoint, int]] = []
    unavailable: list[IperfEndpoint] = []
    workers = min(12, max(1, len(endpoints)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(find_open_port, endpoint.host, endpoint.ports): endpoint
            for endpoint in endpoints
        }
        for future in concurrent.futures.as_completed(futures):
            endpoint = futures[future]
            port = future.result()
            if port is None:
                unavailable.append(endpoint)
            elif limit is None or len(selected) < limit:
                selected.append((endpoint, port))
    selected.sort(key=lambda item: (item[0].city, item[0].name))
    unavailable.sort(key=lambda item: (item.city, item.name))
    return selected, unavailable


def _endpoint_priority(endpoint: IperfEndpoint) -> tuple[int, str]:
    name = endpoint.name.casefold()
    for priority, provider in enumerate(("hostkey", "mts", "ttk", "beeline", "ertelecom")):
        if provider in name:
            return priority, name
    return 10, name


def resolve_available_by_city(
    endpoints: list[IperfEndpoint],
) -> tuple[list[tuple[IperfEndpoint, int]], list[str]]:
    groups: dict[str, list[IperfEndpoint]] = {}
    for endpoint in endpoints:
        groups.setdefault(endpoint.city, []).append(endpoint)

    def resolve(item: tuple[str, list[IperfEndpoint]]) -> tuple[str, IperfEndpoint | None, int | None]:
        city, candidates = item
        for endpoint in sorted(candidates, key=_endpoint_priority):
            port = find_working_iperf_port(endpoint.host, endpoint.ports)
            if port is not None:
                return city, endpoint, port
        return city, None, None

    selected: list[tuple[IperfEndpoint, int]] = []
    unavailable: list[str] = []
    workers = min(8, max(1, len(groups)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for city, endpoint, port in executor.map(resolve, groups.items()):
            if endpoint is None or port is None:
                unavailable.append(city)
            else:
                selected.append((endpoint, port))
    selected.sort(key=lambda item: item[0].city)
    unavailable.sort()
    return selected, unavailable


def choose_public_iperf_endpoints(
    profile: str | None = None,
    cities: list[str] | None = None,
    *,
    online: bool = True,
) -> tuple[list[IperfEndpoint], str]:
    catalog, source_mode = load_ru_iperf_catalog(online=online)
    requested = cities or IPERF_PROFILES.get(profile or "ru-core", IPERF_PROFILES["ru-core"])
    selected = filter_iperf_catalog(catalog, requested)
    missing = [city for city in requested if not any(item.city.casefold() == city.casefold() for item in selected)]
    if missing:
        raise ValueError(f"Города отсутствуют в каталоге: {', '.join(missing)}")
    return selected, source_mode


def parse_ping_output(output: str) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {}
    packets = re.search(
        r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received.*?([\d.]+)% packet loss",
        output,
        re.IGNORECASE | re.DOTALL,
    )
    if packets:
        metrics.update(
            transmitted=int(packets.group(1)),
            received=int(packets.group(2)),
            loss_percent=float(packets.group(3)),
        )
    timing = re.search(
        r"(?:rtt|round-trip).*?=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    if timing:
        metrics.update(
            min_ms=float(timing.group(1)),
            avg_ms=float(timing.group(2)),
            max_ms=float(timing.group(3)),
            jitter_ms=float(timing.group(4)),
        )
    if not packets:
        windows_packets = re.search(
            r"(?:Packets|Пакетов):\s*(?:Sent|отправлено)\s*=\s*(\d+),\s*"
            r"(?:Received|получено)\s*=\s*(\d+),\s*(?:Lost|потеряно)\s*=\s*\d+\s*"
            r"\(([\d.]+)%\s*(?:loss|потерь)\)",
            output,
            re.IGNORECASE,
        )
        if windows_packets:
            metrics.update(
                transmitted=int(windows_packets.group(1)),
                received=int(windows_packets.group(2)),
                loss_percent=float(windows_packets.group(3)),
            )
    if not timing:
        windows_timing = re.search(
            r"(?:Minimum|Минимальное)\s*=\s*([\d.]+)\s*(?:ms|мсек),\s*"
            r"(?:Maximum|Максимальное)\s*=\s*([\d.]+)\s*(?:ms|мсек),\s*"
            r"(?:Average|Среднее)\s*=\s*([\d.]+)\s*(?:ms|мсек)",
            output,
            re.IGNORECASE,
        )
        if windows_timing:
            metrics.update(
                min_ms=float(windows_timing.group(1)),
                max_ms=float(windows_timing.group(2)),
                avg_ms=float(windows_timing.group(3)),
            )
    if "jitter_ms" not in metrics:
        reply_times = [
            float(value.replace(",", "."))
            for value in re.findall(
                r"(?:time|время)\s*[=<]\s*([\d.,]+)\s*(?:ms|мс|мсек)",
                output,
                re.IGNORECASE,
            )
        ]
        if len(reply_times) >= 2:
            metrics["jitter_ms"] = round(statistics.pstdev(reply_times), 3)
    return metrics


def parse_mtr_output(output: str) -> dict[str, float | int]:
    metrics: dict[str, float | int] = {}
    lines = [line for line in output.splitlines() if re.match(r"^\s*\d+\.\|--", line)]
    if not lines:
        return metrics
    last = re.search(
        r"^\s*(\d+)\.\|--\s+\S+\s+([\d.]+)%\s+(\d+)\s+"
        r"[\d.]+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
        lines[-1],
    )
    if last:
        metrics.update(
            hops=int(last.group(1)),
            destination_loss_percent=float(last.group(2)),
            probes=int(last.group(3)),
            avg_ms=float(last.group(4)),
            best_ms=float(last.group(5)),
            worst_ms=float(last.group(6)),
            jitter_ms=float(last.group(7)),
        )
    return metrics


def parse_iperf_json(output: str, *, udp: bool = False) -> dict[str, Any]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        # Some builds print a warning around the JSON document on stderr.  The
        # command runner preserves stderr for diagnostics, so decode the first
        # complete JSON object instead of losing otherwise valid measurements.
        brace = output.find("{")
        if brace < 0:
            return {}
        try:
            payload, _ = json.JSONDecoder().raw_decode(output[brace:])
        except json.JSONDecodeError:
            return {}
    if payload.get("error"):
        return {"error": str(payload["error"])}
    end = payload.get("end", {})
    if udp:
        summary = end.get("sum_received") or end.get("sum") or end.get("sum_sent") or {}
    else:
        summary = end.get("sum_received") or end.get("sum") or end.get("sum_sent") or {}
    metrics: dict[str, Any] = {}
    if isinstance(summary.get("bits_per_second"), (int, float)):
        metrics["mbps"] = round(float(summary["bits_per_second"]) / 1_000_000, 2)
    if isinstance(summary.get("bytes"), (int, float)):
        metrics["transferred_bytes"] = int(summary["bytes"])
    if isinstance(summary.get("seconds"), (int, float)):
        metrics["measured_seconds"] = round(float(summary["seconds"]), 3)
    if udp:
        for source, destination in (
            ("jitter_ms", "jitter_ms"),
            ("lost_percent", "loss_percent"),
            ("lost_packets", "lost_packets"),
            ("packets", "packets"),
        ):
            if source in summary:
                metrics[destination] = summary[source]
    sent = end.get("sum_sent", {})
    if "retransmits" in sent:
        metrics["retransmits"] = int(sent["retransmits"])
        sent_bytes = sent.get("bytes")
        if isinstance(sent_bytes, (int, float)) and float(sent_bytes) > 0:
            gib = float(sent_bytes) / (1024**3)
            metrics["retransmits_per_gib"] = round(metrics["retransmits"] / gib, 2)
    test_start = payload.get("start", {}).get("test_start", {})
    if isinstance(test_start.get("num_streams"), int):
        metrics["streams"] = int(test_start["num_streams"])
    interval_mbps: list[float] = []
    interval_retransmits: list[int] = []
    for interval in payload.get("intervals", []):
        interval_summary = interval.get("sum") or interval.get("sum_received") or {}
        if interval_summary.get("omitted"):
            continue
        bits_per_second = interval_summary.get("bits_per_second")
        if isinstance(bits_per_second, (int, float)):
            interval_mbps.append(round(float(bits_per_second) / 1_000_000, 2))
        retransmits = interval_summary.get("retransmits")
        if isinstance(retransmits, int):
            interval_retransmits.append(retransmits)
    if interval_mbps:
        metrics["interval_mbps"] = interval_mbps
        metrics["interval_min_mbps"] = min(interval_mbps)
        metrics["interval_max_mbps"] = max(interval_mbps)
        average = statistics.mean(interval_mbps)
        metrics["interval_cv_percent"] = (
            round(statistics.pstdev(interval_mbps) / average * 100, 2) if average else 0.0
        )
        section_size = max(1, len(interval_mbps) // 4)
        first = statistics.mean(interval_mbps[:section_size])
        last = statistics.mean(interval_mbps[-section_size:])
        metrics["first_interval_avg_mbps"] = round(first, 2)
        metrics["last_interval_avg_mbps"] = round(last, 2)
        metrics["sustained_drop_percent"] = (
            round(max(0.0, (first - last) / first * 100), 2) if first else 0.0
        )
    if interval_retransmits:
        metrics["interval_retransmits"] = interval_retransmits
    cpu = end.get("cpu_utilization_percent", {})
    if isinstance(cpu.get("host_total"), (int, float)):
        metrics["local_cpu_percent"] = round(float(cpu["host_total"]), 2)
    return metrics


def parse_openssl_speed(output: str) -> float | None:
    """Return decimal MB/s from OpenSSL speed output.

    Prefer the machine-readable ``+F:`` summary. The human fallback requires
    an actual throughput suffix so digits in cipher names or error messages
    (AES-256-GCM, ChaCha20-Poly1305) can never be mistaken for a benchmark.
    """
    for line in reversed(output.splitlines()):
        if not line.startswith("+F:") or not re.search(
            r"(?:AES-256-GCM|ChaCha20-Poly1305)", line, re.IGNORECASE
        ):
            continue
        fields = line.split(":")
        for field in reversed(fields):
            try:
                bytes_per_second = float(field)
            except ValueError:
                continue
            if math.isfinite(bytes_per_second) and bytes_per_second > 0:
                return bytes_per_second / 1_000_000

    for line in reversed(output.splitlines()):
        match = re.match(
            r"^\s*(?:AES-256-GCM|ChaCha20-Poly1305)\s+(.+?)\s*$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        tokens = re.findall(r"(?<![\w.-])(\d+(?:[.,]\d+)?)([kKmMgG])(?:\s|$)", match.group(1))
        if not tokens:
            continue
        value, suffix = tokens[-1]
        multiplier = {"k": 1_000.0, "m": 1_000_000.0, "g": 1_000_000_000.0}
        bytes_per_second = float(value.replace(",", ".")) * multiplier[suffix.lower()]
        if math.isfinite(bytes_per_second) and bytes_per_second > 0:
            return bytes_per_second / 1_000_000
    return None


def _crypto_benchmark_assessment(mbps: float | None) -> tuple[str, str]:
    if mbps is None or not math.isfinite(mbps) or mbps <= 0:
        return "failed", "Скорость шифрования не измерена"
    if mbps < 500:
        return "bad", "Очень низкая однопоточная скорость шифрования"
    if mbps < 1_500:
        return "warning", "Скорость достаточна только для умеренной VPN-нагрузки"
    return "ok", "Хорошая однопоточная скорость шифрования"


def _crypto_benchmark_score(mbps: float) -> float:
    points = [
        (0.0, 0.0),
        (250.0, 15.0),
        (500.0, 35.0),
        (1_000.0, 60.0),
        (1_500.0, 75.0),
        (3_000.0, 90.0),
        (5_000.0, 100.0),
    ]
    value = max(0.0, mbps)
    for index in range(1, len(points)):
        lower_speed, lower_score = points[index - 1]
        upper_speed, upper_score = points[index]
        if value <= upper_speed:
            share = (value - lower_speed) / (upper_speed - lower_speed)
            return lower_score + share * (upper_score - lower_score)
    return 100.0


def _finalize_crypto_benchmark(item: TestResult) -> TestResult:
    if item.status != "ok":
        return item
    mb_per_sec = parse_openssl_speed(item.output)
    throughput_mbps = mb_per_sec * 8 if mb_per_sec is not None else None
    status, assessment = _crypto_benchmark_assessment(throughput_mbps)
    if throughput_mbps is None:
        item.status = "failed"
        item.summary = (
            "OpenSSL завершился без распознаваемой положительной скорости; "
            "результат не засчитан"
        )
        return item
    item.metrics.update(
        mb_per_sec=round(mb_per_sec, 2),
        throughput_mbps=round(throughput_mbps, 2),
        estimated_gbps=round(throughput_mbps / 1_000, 4),
    )
    item.status = status
    item.summary = (
        f"{throughput_mbps:.1f} Мбит/с на блоках 16 KiB "
        f"(синтетика одного процесса) — {assessment.lower()}"
    )
    return item


def _ping_assessment(metrics: dict[str, Any]) -> tuple[str, str]:
    if "loss_percent" not in metrics:
        return "failed", "Не удалось разобрать статистику ping"
    loss = float(metrics["loss_percent"])
    avg = metrics.get("avg_ms")
    jitter = metrics.get("jitter_ms")
    if loss > 2:
        status = "bad"
    elif loss > 0 or (avg is not None and avg > 120) or (jitter is not None and jitter > 20):
        status = "warning"
    else:
        status = "ok"
    if loss >= 100:
        return "bad", "100% потерь: цель не отвечает на ICMP (ping может фильтроваться firewall)"
    details = [f"потери {loss:g}%"]
    if avg is not None:
        details.insert(0, f"RTT avg {avg:g} мс")
    if jitter is not None:
        details.append(f"разброс {jitter:g} мс")
    return status, ", ".join(details)


def _base_environment() -> dict[str, str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env


def run_ping(runner: CommandRunner, target: str, count: int) -> TestResult:
    ip_version = "-6" if _is_ipv6(target) else "-4"
    if os.name == "nt":
        windows_ip_version = "-6" if _is_ipv6(target) else "-4"
        args = ["ping", windows_ip_version, "-n", str(count), "-w", "2000", target]
    else:
        args = ["ping", ip_version, "-n", "-c", str(count), "-i", "0.2", "-W", "2", target]
    result = runner.run(
        f"Ping → {target}",
        "ping",
        args,
        timeout=max(15, count * 3),
        env=_base_environment(),
    )
    metrics = parse_ping_output(result.output)
    result.metrics.update(metrics)
    if metrics:
        result.status, result.summary = _ping_assessment(metrics)
    return result


def run_mtr(runner: CommandRunner, target: str, count: int) -> TestResult:
    ip_version = "-6" if _is_ipv6(target) else "-4"
    result = runner.run(
        f"MTR → {target}",
        "mtr",
        ["mtr", ip_version, "-n", "-r", "-w", "-c", str(count), target],
        timeout=max(30, count * 3),
        env=_base_environment(),
    )
    metrics = parse_mtr_output(result.output)
    result.metrics.update(metrics)
    if result.status == "ok":
        if metrics:
            destination_loss = float(metrics["destination_loss_percent"])
            if destination_loss > 2:
                result.status = "bad"
            elif destination_loss > 0:
                result.status = "warning"
            result.summary = (
                f"{metrics['hops']} хопов, RTT avg {metrics['avg_ms']:g} мс, "
                f"потери до цели {destination_loss:g}%; "
                "потери на промежуточных хопах могут быть ICMP rate-limit"
            )
        else:
            result.summary = "Маршрут получен; автоматический разбор недоступен, смотрите сырой вывод"
    return result


def run_traceroute(runner: CommandRunner, target: str) -> TestResult:
    ip_version = "-6" if _is_ipv6(target) else "-4"
    if os.name == "nt":
        windows_ip_version = "-6" if _is_ipv6(target) else "-4"
        args = ["tracert", windows_ip_version, "-d", "-w", "1000", "-h", "30", target]
        label = f"Traceroute → {target} (Windows ICMP)"
    else:
        args = [
            "traceroute",
            ip_version,
            "-n",
            "-T",
            "-p",
            "443",
            "-w",
            "1",
            "-q",
            "1",
            "-m",
            "30",
            target,
        ]
        label = f"TCP traceroute:443 → {target}"
    result = runner.run(
        label,
        "traceroute",
        args,
        timeout=45,
        env=_base_environment(),
    )
    hop_lines = [
        line.rstrip()
        for line in result.output.splitlines()
        if re.match(r"^\s*\d+\s+", line)
    ]
    if hop_lines:
        result.metrics["hops_shown"] = len(hop_lines)
        result.metrics["hop_lines"] = hop_lines
        result.metrics["hop_rows"] = _traceroute_hop_rows(hop_lines)
    if result.status == "ok":
        hops = len(hop_lines)
        protocol = "Windows tracert/ICMP" if os.name == "nt" else "TCP/443"
        result.summary = f"Показано {hops} хопов по {protocol}"
    return result


def run_tcp_probe(
    target: str,
    port: int = 443,
    attempts: int = 5,
    *,
    announce: bool = True,
) -> TestResult:
    if announce:
        _stage_output(f"\n▶ DNS + TCP/{port} → {target}")
    started = time.monotonic()
    dns_samples: list[float] = []
    tcp_samples: list[float] = []
    addresses: set[str] = set()
    errors: list[str] = []
    for _ in range(attempts):
        dns_started = time.monotonic()
        try:
            infos = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
            dns_samples.append((time.monotonic() - dns_started) * 1000)
            addresses.update(str(info[4][0]) for info in infos)
            family, socktype, protocol, _, sockaddr = infos[0]
            connect_started = time.monotonic()
            with socket.socket(family, socktype, protocol) as connection:
                connection.settimeout(3)
                connection.connect(sockaddr)
                tcp_samples.append((time.monotonic() - connect_started) * 1000)
        except OSError as exc:
            errors.append(str(exc))
        time.sleep(0.1)
    elapsed = round(time.monotonic() - started, 3)
    metrics: dict[str, Any] = {
        "port": port,
        "attempts": attempts,
        "successful_connections": len(tcp_samples),
        "addresses": sorted(addresses),
    }
    if dns_samples:
        metrics["dns_avg_ms"] = round(statistics.mean(dns_samples), 2)
    if tcp_samples:
        metrics.update(
            tcp_avg_ms=round(statistics.mean(tcp_samples), 2),
            tcp_min_ms=round(min(tcp_samples), 2),
            tcp_max_ms=round(max(tcp_samples), 2),
        )
    success = len(tcp_samples)
    if success == attempts:
        status = "ok"
    elif success:
        status = "warning"
    else:
        status = "failed"
    summary = f"TCP успешно {success}/{attempts}"
    if tcp_samples:
        summary += f", handshake avg {metrics['tcp_avg_ms']} мс"
    output = "Адреса: " + (", ".join(sorted(addresses)) or "нет")
    if errors:
        output += "\nОшибки: " + " | ".join(dict.fromkeys(errors))
    if announce:
        _stage_output(f"  {summary}", summary)
    return TestResult(
        name=f"DNS + TCP/{port} → {target}",
        category="tcp",
        status=status,
        summary=summary,
        elapsed_seconds=elapsed,
        metrics=metrics,
        output=output,
    )


def _udp_probe_payload(port: int) -> bytes:
    if port == 53:
        return _dns_query_packet("example.com", time.time_ns() & 0xFFFF)
    return b"server-suitability-audit\0"


def run_udp_port_probe(
    target: str,
    port: int = 443,
    attempts: int = 3,
    *,
    timeout: float = 1.0,
    announce: bool = True,
) -> TestResult:
    """Probe UDP without pretending that silence proves an open or closed port."""
    if announce:
        _stage_output(f"\n▶ DNS + UDP/{port} → {target}")
    started = time.monotonic()
    addresses: set[str] = set()
    response_samples: list[float] = []
    refusals = 0
    timeouts = 0
    errors: list[str] = []
    try:
        infos = socket.getaddrinfo(target, port, type=socket.SOCK_DGRAM)
    except OSError as exc:
        infos = []
        errors.append(str(exc))
    payload = _udp_probe_payload(port)
    for attempt in range(attempts):
        if not infos:
            break
        family, socktype, protocol, _, sockaddr = infos[attempt % len(infos)]
        addresses.add(str(sockaddr[0]))
        probe_started = time.monotonic()
        try:
            with socket.socket(family, socktype, protocol) as connection:
                connection.settimeout(timeout)
                connection.connect(sockaddr)
                connection.send(payload)
                response = connection.recv(2048)
                if response:
                    response_samples.append((time.monotonic() - probe_started) * 1000)
        except socket.timeout:
            timeouts += 1
        except OSError as exc:
            error_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            if isinstance(exc, ConnectionRefusedError) or error_code in {61, 111, 10054}:
                refusals += 1
            else:
                errors.append(str(exc))
        if attempt < attempts - 1:
            time.sleep(0.05)

    metrics: dict[str, Any] = {
        "protocol": "UDP",
        "port": port,
        "attempts": attempts,
        "responses": len(response_samples),
        "timeouts": timeouts,
        "refusals": refusals,
        "addresses": sorted(addresses),
    }
    if response_samples:
        metrics["response_avg_ms"] = round(statistics.mean(response_samples), 2)
        status = "ok"
        summary = f"UDP-сервис ответил {len(response_samples)}/{attempts} раз"
    elif refusals:
        status = "bad"
        summary = "Получен ICMP/системный отказ: UDP-порт закрыт или недоступен"
    elif infos:
        status = "warning"
        summary = "UDP не ответил: порт может быть открыт, фильтроваться или игнорировать пробный пакет"
    else:
        status = "failed"
        summary = "Не удалось определить адрес цели через DNS"
    if errors:
        metrics["errors"] = list(dict.fromkeys(errors))
    if announce:
        _stage_output(f"  {summary}", summary)
    return TestResult(
        name=f"UDP/{port} → {target}",
        category="udp_port",
        status=status,
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics=metrics,
        output=json.dumps(metrics, ensure_ascii=False),
    )


def run_pmtu(runner: CommandRunner, target: str) -> TestResult:
    if _is_ipv6(target):
        return TestResult(
            name=f"Path MTU → {target}",
            category="pmtu",
            status="skipped",
            summary="Автоматическая PMTU-проба сейчас поддерживает IPv4-цели",
        )
    if shutil.which("ping") is None:
        return TestResult(
            name=f"Path MTU → {target}",
            category="pmtu",
            status="skipped",
            summary="Команда ping не установлена",
        )
    _stage_output(f"\n▶ Path MTU → {target}")
    started = time.monotonic()
    low, high = 1200, 1472
    successful = None
    attempts: list[dict[str, Any]] = []
    while low <= high:
        size = (low + high) // 2
        if os.name == "nt":
            args = ["ping", "-4", "-n", "1", "-w", "2000", "-f", "-l", str(size), target]
        else:
            args = ["ping", "-4", "-n", "-c", "1", "-W", "2", "-M", "do", "-s", str(size), target]
        probe = runner.run(
            f"PMTU payload {size}",
            "pmtu-probe",
            args,
            timeout=5,
            env=_base_environment(),
        )
        ok = probe.status == "ok" and parse_ping_output(probe.output).get("received") == 1
        attempts.append({"payload_bytes": size, "success": ok})
        if ok:
            successful = size
            low = size + 1
        else:
            high = size - 1
    elapsed = round(time.monotonic() - started, 3)
    if successful is None:
        status = "warning"
        summary = "ICMP/DF заблокирован или MTU ниже 1228; результат не определён"
        metrics: dict[str, Any] = {"attempts": attempts}
    else:
        pmtu = successful + 28
        status = "ok" if pmtu >= 1400 else "warning"
        summary = f"Оценочный IPv4 Path MTU: {pmtu} байт"
        metrics = {"path_mtu_bytes": pmtu, "max_icmp_payload_bytes": successful, "attempts": attempts}
    _stage_output(f"  {summary}", summary)
    return TestResult(
        name=f"Path MTU → {target}",
        category="pmtu",
        status=status,
        summary=summary,
        elapsed_seconds=elapsed,
        metrics=metrics,
        output=json.dumps(attempts, ensure_ascii=False),
    )


def run_iperf(
    runner: CommandRunner,
    host: str,
    port: int,
    seconds: int,
    streams: int,
    *,
    reverse: bool = False,
    udp_mbps: int | None = None,
) -> TestResult:
    direction = "download" if reverse else "upload"
    run_label = direction
    if udp_mbps is not None:
        run_label = f"UDP {udp_mbps} Mbps {'download' if reverse else 'upload'}"
    args = [
        "iperf3",
        "-c",
        host,
        "-p",
        str(port),
        "-J",
        "-t",
        str(seconds),
        "-O",
        "2",
    ]
    if udp_mbps is None:
        args.extend(["-P", str(streams)])
    else:
        args.extend(["-u", "-b", f"{udp_mbps}M"])
    if reverse:
        args.append("-R")
    result = runner.run(
        f"iperf3 {run_label} ↔ {host}:{port}",
        "udp" if udp_mbps is not None else "iperf",
        args,
        timeout=seconds + 20,
        env=_base_environment(),
    )
    metrics = parse_iperf_json(result.output, udp=udp_mbps is not None)
    result.metrics.update(metrics)
    result.metrics["direction"] = direction
    result.metrics["duration_seconds"] = seconds
    result.metrics["streams"] = 1 if udp_mbps is not None else streams
    if udp_mbps is not None:
        result.metrics["requested_mbps"] = udp_mbps
    if metrics.get("error"):
        result.status = "failed"
        result.summary = str(metrics["error"])
    elif "mbps" in metrics:
        if udp_mbps is not None:
            loss = float(metrics.get("loss_percent", 0))
            result.status = "ok" if loss <= 0.5 else "warning" if loss <= 2 else "bad"
            result.summary = (
                f"{metrics['mbps']} Mbps, потери {loss:g}%, "
                f"jitter {float(metrics.get('jitter_ms', 0)):g} мс"
            )
        else:
            result.status = "ok"
            result.summary = f"{metrics['mbps']} Mbps ({direction}), {streams} TCP-потока(ов)"
            if "retransmits" in metrics:
                result.summary += f", TCP-повторы {metrics['retransmits']}"
                if metrics.get("retransmits_per_gib") is not None:
                    result.summary += f" ({metrics['retransmits_per_gib']:g}/ГиБ)"
    elif result.status == "ok":
        result.status = "failed"
        result.summary = "iperf3 завершился без распознаваемой итоговой статистики"
    return result


def run_iperf_endpoint(
    runner: CommandRunner,
    endpoint: IperfEndpoint,
    port: int,
    seconds: int,
    *,
    stream_profiles: tuple[int, ...] = IPERF_TCP_STREAM_PROFILES,
    include_udp: bool = False,
    udp_mbps: int = 50,
) -> list[TestResult]:
    results: list[TestResult] = []
    for streams in stream_profiles:
        results.extend(
            [
                run_iperf(runner, endpoint.host, port, seconds, streams),
                run_iperf(runner, endpoint.host, port, seconds, streams, reverse=True),
            ]
        )
    for result in results:
        result.metrics["endpoint"] = endpoint.as_dict()
        result.metrics["selected_port"] = port
        result.name = f"{result.name} [{endpoint.city}, {endpoint.name}]"
    if include_udp and (not endpoint.public or endpoint.supports_udp):
        udp_results = [
            run_iperf(runner, endpoint.host, port, seconds, 1, udp_mbps=udp_mbps),
            run_iperf(
                runner,
                endpoint.host,
                port,
                seconds,
                1,
                reverse=True,
                udp_mbps=udp_mbps,
            ),
        ]
        for result in udp_results:
            result.metrics["endpoint"] = endpoint.as_dict()
            result.metrics["selected_port"] = port
            result.name = f"{result.name} [{endpoint.city}, {endpoint.name}]"
        results.extend(udp_results)
    elif include_udp and endpoint.public:
        results.append(
            TestResult(
                name=f"iperf3 UDP [{endpoint.city}, {endpoint.name}]",
                category="udp",
                status="skipped",
                summary="UDP не заявлен владельцем публичной точки; тест не создаёт нежелательную нагрузку",
                metrics={"endpoint": endpoint.as_dict(), "selected_port": port},
            )
        )
    return results


def _network_soak_stability_result(
    target: str,
    port: int,
    duration_seconds: int,
    windows: list[dict[str, Any]],
    elapsed_seconds: float,
) -> TestResult:
    transmitted = sum(int(item.get("ping", {}).get("transmitted", 0)) for item in windows)
    received = sum(int(item.get("ping", {}).get("received", 0)) for item in windows)
    loss = round((transmitted - received) / transmitted * 100, 2) if transmitted else 100.0
    rtt_values = [
        float(item["ping"]["avg_ms"])
        for item in windows
        if item.get("ping", {}).get("avg_ms") is not None
    ]
    average_rtt = round(statistics.mean(rtt_values), 2) if rtt_values else None
    max_rtt = max(rtt_values) if rtt_values else None
    p95_rtt = None
    spike_windows = 0
    if rtt_values:
        ordered = sorted(rtt_values)
        p95_rtt = ordered[min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)]
        baseline = statistics.median(rtt_values)
        spike_limit = max(baseline * 1.75, baseline + 20)
        spike_windows = sum(value > spike_limit for value in rtt_values)
    tcp_attempts = sum(int(item.get("tcp", {}).get("attempts", 0)) for item in windows)
    tcp_successes = sum(
        int(item.get("tcp", {}).get("successful_connections", 0)) for item in windows
    )
    tcp_success_percent = round(tcp_successes / tcp_attempts * 100, 2) if tcp_attempts else 0.0
    outage_windows = sum(
        1
        for item in windows
        if float(item.get("ping", {}).get("loss_percent", 100)) >= 100
        and int(item.get("tcp", {}).get("successful_connections", 0)) == 0
    )
    if outage_windows >= 2 or (loss > 5 and tcp_success_percent < 80):
        status = "bad"
    elif loss > 0.5 or tcp_success_percent < 100 or spike_windows:
        status = "warning"
    else:
        status = "ok"
    summary = (
        f"{len(windows)} интервалов, потери {loss:g}%, "
        f"TCP {tcp_successes}/{tcp_attempts}, всплески RTT {spike_windows}"
    )
    return TestResult(
        name=f"Длительная стабильность → {target}",
        category="soak",
        status=status,
        summary=summary,
        elapsed_seconds=round(elapsed_seconds, 3),
        metrics={
            "target": target,
            "port": port,
            "requested_duration_seconds": duration_seconds,
            "sample_windows": len(windows),
            "ping_transmitted": transmitted,
            "ping_received": received,
            "loss_percent": loss,
            "avg_ms": average_rtt,
            "p95_ms": p95_rtt,
            "max_window_avg_ms": max_rtt,
            "rtt_spike_windows": spike_windows,
            "tcp_attempts": tcp_attempts,
            "tcp_successes": tcp_successes,
            "tcp_success_percent": tcp_success_percent,
            "outage_windows": outage_windows,
            "windows": windows,
        },
    )


def _network_soak_iperf_result(
    host: str,
    port: int,
    streams: int,
    duration_seconds: int,
    command: list[str],
    return_code: int,
    output: str,
    expected_mbps: int,
) -> TestResult:
    metrics = parse_iperf_json(output)
    metrics.update(
        {
            "endpoint_host": host,
            "selected_port": port,
            "streams": streams,
            "duration_seconds": duration_seconds,
            "direction": "upload",
        }
    )
    if return_code != 0 or "mbps" not in metrics:
        status = "failed"
        summary = str(metrics.get("error") or f"iperf3 завершился с кодом {return_code}")
    else:
        speed = float(metrics["mbps"])
        variation = float(metrics.get("interval_cv_percent", 0))
        sustained_drop = float(metrics.get("sustained_drop_percent", 0))
        speed_status = _throughput_status(speed, expected_mbps)
        if speed_status == "ПЛОХО" or sustained_drop >= 40:
            status = "bad"
        elif speed_status == "ВНИМАНИЕ" or sustained_drop >= 20 or variation >= 20:
            status = "warning"
        else:
            status = "ok"
        summary = (
            f"средняя скорость {speed:g} Мбит/с, разброс интервалов {variation:g}%, "
            f"снижение к концу {sustained_drop:g}%"
        )
    return TestResult(
        name=f"Длительный iperf3 TCP → {host}:{port}",
        category="soak_iperf",
        status=status,
        summary=summary,
        command=shlex.join(command),
        elapsed_seconds=float(duration_seconds),
        metrics=metrics,
        output=output,
    )


def run_network_soak(
    runner: CommandRunner,
    target: str,
    port: int,
    duration_seconds: int = 300,
    interval_seconds: int = 15,
    *,
    iperf_host: str | None = None,
    iperf_port: int = 5201,
    streams: int = 4,
    expected_mbps: int = 0,
) -> list[TestResult]:
    """Observe latency/TCP throughout the run and optionally load the path with iperf3."""
    interval_seconds = max(1, interval_seconds)
    _stage_output(f"\n▶ Длительный сетевой тест ({duration_seconds} с) → {target}")
    started = time.monotonic()
    deadline = started + duration_seconds
    iperf_process: subprocess.Popen[bytes] | None = None
    iperf_command: list[str] | None = None
    iperf_launch_error: str | None = None
    if iperf_host and shutil.which("iperf3") is not None:
        iperf_command = [
            "iperf3",
            "-c",
            iperf_host,
            "-p",
            str(iperf_port),
            "-J",
            "-t",
            str(duration_seconds),
            "-O",
            "2",
            "-i",
            str(max(1, interval_seconds)),
            "-P",
            str(streams),
        ]
        try:
            iperf_process = subprocess.Popen(
                iperf_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_base_environment(),
            )
        except OSError as exc:
            iperf_launch_error = str(exc)

    windows: list[dict[str, Any]] = []
    next_sample = started
    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if windows and now < next_sample:
                time.sleep(min(next_sample, deadline) - now)
                continue
            sample_started = time.monotonic()
            ping = run_ping(runner, target, 3)
            tcp = run_tcp_probe(target, port, attempts=1, announce=False)
            windows.append(
                {
                    "at_seconds": round(sample_started - started, 2),
                    "ping": ping.metrics,
                    "ping_status": ping.status,
                    "tcp": tcp.metrics,
                    "tcp_status": tcp.status,
                }
            )
            if _ACTIVE_PROGRESS:
                _ACTIVE_PROGRESS.detail(
                    f"Длительный тест: интервал {len(windows)}, прошло {_format_duration(time.monotonic() - started)}"
                )
            next_sample += interval_seconds
    except BaseException:
        if iperf_process and iperf_process.poll() is None:
            iperf_process.terminate()
        raise

    elapsed = time.monotonic() - started
    results = [
        _network_soak_stability_result(target, port, duration_seconds, windows, elapsed)
    ]
    if iperf_process and iperf_command:
        try:
            stdout, stderr = iperf_process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            iperf_process.kill()
            stdout, stderr = iperf_process.communicate()
        output = _combine_output(stdout, stderr)
        results.append(
            _network_soak_iperf_result(
                iperf_host or "неизвестная точка",
                iperf_port,
                streams,
                duration_seconds,
                iperf_command,
                int(iperf_process.returncode or 0),
                output,
                expected_mbps,
            )
        )
    elif iperf_host:
        results.append(
            TestResult(
                name="Длительный iperf3 TCP",
                category="soak_iperf",
                status="skipped",
                summary=(
                    f"Не удалось запустить iperf3: {iperf_launch_error}"
                    if iperf_launch_error
                    else "Команда iperf3 не установлена; burst-лимит скорости не проверен"
                ),
                metrics={"endpoint_host": iperf_host, "selected_port": iperf_port},
            )
        )
    else:
        results.append(
            TestResult(
                name="Длительный iperf3 TCP",
                category="soak_iperf",
                status="skipped",
                summary="Собственный iperf3-сервер не указан; проверены задержка, потери и TCP, но не burst-лимит скорости",
            )
        )
    return results


def _flatten_ipapi_is(payload: dict[str, Any]) -> dict[str, Any]:
    location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
    asn = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
    company = payload.get("company") if isinstance(payload.get("company"), dict) else {}
    return {
        # ipapi.is currently returns a compact flat response, while older and
        # paid response variants may contain nested location/asn objects.
        "country": payload.get("cc") or location.get("country_code") or location.get("country"),
        "region": payload.get("state") or location.get("state") or location.get("region"),
        "city": payload.get("city") or location.get("city"),
        "asn": payload.get("asn_num") or asn.get("asn") or asn.get("number"),
        "organization": (
            payload.get("asn_org")
            or payload.get("company_name")
            or asn.get("org")
            or asn.get("name")
            or company.get("name")
        ),
        "company_type": payload.get("company_type") or company.get("type") or asn.get("type"),
        "is_datacenter": payload.get("is_datacenter"),
        "is_vpn": payload.get("is_vpn"),
        "is_proxy": payload.get("is_proxy"),
        "is_tor": payload.get("is_tor"),
        "is_abuser": payload.get("is_abuser"),
        "is_bogon": payload.get("is_bogon"),
    }


def _flatten_ipwhois(payload: dict[str, Any]) -> dict[str, Any]:
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    security = payload.get("security") if isinstance(payload.get("security"), dict) else {}
    return {
        "country": payload.get("country_code"),
        "region": payload.get("region"),
        "city": payload.get("city"),
        "asn": connection.get("asn"),
        "organization": connection.get("org") or connection.get("isp"),
        **{f"is_{key}": security.get(key) for key in ("hosting", "vpn", "proxy", "tor")},
    }


def _flatten_ipapi_co(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "country": payload.get("country_code") or payload.get("country"),
        "region": payload.get("region"),
        "city": payload.get("city"),
        "asn": payload.get("asn"),
        "organization": payload.get("org"),
    }


def _rdap_summary(payload: dict[str, Any]) -> dict[str, Any]:
    entities: list[str] = []
    for entity in payload.get("entities", []):
        if not isinstance(entity, dict):
            continue
        handle = entity.get("handle")
        if handle:
            entities.append(str(handle))
    return {
        "handle": payload.get("handle"),
        "name": payload.get("name"),
        "country": payload.get("country"),
        "start_address": payload.get("startAddress"),
        "end_address": payload.get("endAddress"),
        "port43": payload.get("port43"),
        "entities": entities[:10],
    }


def _spamhaus_drop_lookup(ip: str) -> dict[str, Any]:
    version = ipaddress.ip_address(ip).version
    url = f"https://www.spamhaus.org/drop/drop_v{version}.json"
    try:
        content = _http_bytes(url, timeout=10, max_bytes=4_000_000).decode(
            "utf-8", errors="replace"
        )
    except (OSError, urllib.error.URLError):
        return {"checked": False, "listed": None, "source": url}
    address = ipaddress.ip_address(ip)
    for line in content.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in {"[", "]"}:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        cidr = item.get("cidr") if isinstance(item, dict) else None
        try:
            if cidr and address in ipaddress.ip_network(cidr):
                return {"checked": True, "listed": True, "source": url, "record": item}
        except ValueError:
            continue
    return {"checked": True, "listed": False, "source": url}


def _signal_sources(provider_results: dict[str, Any]) -> dict[str, list[str]]:
    keys = ("is_vpn", "is_proxy", "is_tor", "is_abuser", "is_bogon")
    return {
        key: [
            provider
            for provider, data in provider_results.items()
            if not data.get("error") and data.get(key) is True
        ]
        for key in keys
    }


def _country_text(codes: list[str]) -> str:
    if not codes:
        return "не определена"
    return ", ".join(f"{COUNTRY_NAMES_RU.get(code, code)} ({code})" for code in codes)


def _ip_reputation_assessment(
    *,
    countries: list[str],
    signal_sources: dict[str, list[str]],
    spamhaus: dict[str, Any],
    valid_provider_count: int,
) -> tuple[str, int | None, str, list[str], list[str]]:
    """Return status, score, plain verdict, concerns, and positive checks."""
    concerns: list[str] = []
    positives: list[str] = []
    if valid_provider_count == 0:
        return (
            "failed",
            None,
            "репутацию оценить не удалось — внешние базы не ответили",
            ["нет данных от геобаз; проверьте интернет и повторите тест"],
            [],
        )
    score = 100
    if valid_provider_count:
        positives.append(f"успешно ответили геобазы: {valid_provider_count} из 3")
    if len(countries) == 1:
        positives.append(f"страна во всех ответивших геобазах: {_country_text(countries)}")
    if len(countries) > 1:
        score -= 25
        concerns.append("геобазы не согласны по стране IP")
    if spamhaus.get("listed") is True:
        score -= 60
        concerns.append("подсеть находится в Spamhaus DROP — это серьёзный риск")
    elif spamhaus.get("checked") is True:
        positives.append("подсеть не найдена в Spamhaus DROP")

    labels = {
        "is_vpn": "VPN",
        "is_proxy": "proxy",
        "is_tor": "Tor",
        "is_abuser": "abuse",
        "is_bogon": "bogon",
    }
    single_source_labels: dict[tuple[str, ...], list[str]] = {}
    for key, sources in signal_sources.items():
        if not sources:
            continue
        corroborated = len(sources) >= 2
        penalty = {
            "is_vpn": 8,
            "is_proxy": 12,
            "is_tor": 35,
            "is_abuser": 20,
            "is_bogon": 50,
        }[key]
        score -= penalty * (2 if corroborated else 1)
        source_text = ", ".join(sources)
        if corroborated:
            concerns.append(f"несколько баз помечают IP как {labels[key]} ({source_text})")
        else:
            single_source_labels.setdefault(tuple(sources), []).append(labels[key])
    for sources, found_labels in single_source_labels.items():
        concerns.append(
            f"только одна база ({', '.join(sources)}) помечает IP как "
            f"{' и '.join(found_labels)}; это предупреждение, а не доказанный бан"
        )
    if valid_provider_count < 2:
        concerns.append("ответила только одна геобаза, поэтому числовая оценка ненадёжна")
        return (
            "warning",
            None,
            "данных недостаточно для оценки репутации — повторите тест позже",
            concerns,
            positives,
        )
    score = max(0, min(100, score))
    severe = spamhaus.get("listed") is True or any(
        len(signal_sources[key]) >= 2 for key in ("is_tor", "is_abuser", "is_bogon")
    )
    if severe or score < 45:
        status = "bad"
        verdict = "IP рискованный — для основной ноды лучше поискать другой"
    elif concerns:
        status = "warning"
        verdict = "IP условно подходит, но репутацию нужно перепроверить"
    else:
        status = "ok"
        verdict = "явных проблем в проверенных базах не найдено"
    return status, score, verdict, concerns, positives


def run_ip_intelligence(ip: str | None = None) -> TestResult:
    _stage_output("\n▶ IP, геобазы, ASN и базовая репутация")
    started = time.monotonic()
    ip = ip or _public_ip(4) or _public_ip(6)
    if not ip:
        return TestResult(
            name="IP, геобазы и репутация",
            category="ipinfo",
            status="failed",
            summary="Не удалось определить публичный IP",
        )
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return TestResult(
            name="IP, геобазы и репутация",
            category="ipinfo",
            status="failed",
            summary=f"Некорректный IP: {ip}",
        )

    providers = {
        "ipapi.is": (
            f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}",
            _flatten_ipapi_is,
        ),
        "ipwho.is": (
            f"https://ipwho.is/{urllib.parse.quote(ip)}",
            _flatten_ipwhois,
        ),
        "ipapi.co": (
            f"https://ipapi.co/{urllib.parse.quote(ip)}/json/",
            _flatten_ipapi_co,
        ),
    }
    provider_results: dict[str, Any] = {}

    def lookup(item: tuple[str, tuple[str, Any]]) -> tuple[str, dict[str, Any]]:
        name, (url, flatten) = item
        try:
            raw = _http_json(url, timeout=8)
            if raw.get("error") or raw.get("success") is False:
                return name, {"error": raw.get("reason") or raw.get("message") or "API error"}
            return name, flatten(raw)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
            return name, {"error": str(exc)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(providers)) as executor:
        for name, data in executor.map(lookup, providers.items()):
            provider_results[name] = data

    try:
        reverse_dns = socket.gethostbyaddr(ip)[0]
    except OSError:
        reverse_dns = None
    try:
        rdap = _rdap_summary(
            _http_json(f"https://rdap.db.ripe.net/ip/{urllib.parse.quote(ip)}", timeout=10)
        )
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        rdap = {"error": str(exc)}
    spamhaus = _spamhaus_drop_lookup(ip)

    valid = [data for data in provider_results.values() if not data.get("error")]
    countries = sorted({str(data["country"]).upper() for data in valid if data.get("country")})
    cities = sorted({str(data["city"]) for data in valid if data.get("city")})
    asns = sorted({str(data["asn"]).upper().removeprefix("AS") for data in valid if data.get("asn")})
    signal_sources = _signal_sources(provider_results)
    signals = {key: bool(sources) for key, sources in signal_sources.items()}
    hosting = any(
        data.get("is_datacenter") is True
        or data.get("is_hosting") is True
        or str(data.get("company_type", "")).lower() == "hosting"
        for data in valid
    )
    status, reputation_score, verdict, concerns, positives = _ip_reputation_assessment(
        countries=countries,
        signal_sources=signal_sources,
        spamhaus=spamhaus,
        valid_provider_count=len(valid),
    )
    organization = next(
        (str(data["organization"]) for data in valid if data.get("organization")),
        str(rdap.get("name") or rdap.get("handle") or "не определён"),
    )
    if not countries and rdap.get("country"):
        countries = [str(rdap["country"]).upper()]
    summary = verdict
    metrics = {
        "ip": ip,
        "reverse_dns": reverse_dns,
        "countries": countries,
        "cities": cities,
        "asns": asns,
        "hosting_or_datacenter": hosting,
        "organization": organization,
        "reputation_score": reputation_score,
        "verdict": verdict,
        "concerns": concerns,
        "positive_checks": positives,
        "signals": signals,
        "signal_sources": signal_sources,
        "providers": provider_results,
        "rdap": rdap,
        "spamhaus_drop": spamhaus,
        "limitations": [
            "Геолокация и reputation-флаги являются мнением внешних баз и могут устаревать.",
            "Spamhaus DROP — список опасных сетей, а не полная проверка почтовых DNSBL и сервисных банов.",
            "Hosting/datacenter для VPS ожидаем и сам по себе не означает плохой IP.",
        ],
    }
    _stage_output(f"  {ip}: {summary}", summary)
    return TestResult(
        name="IP, геобазы, ASN и базовая репутация",
        category="ipinfo",
        status=status,
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics=metrics,
        output=json.dumps(provider_results, ensure_ascii=False, indent=2),
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _check_url(item: tuple[str, str], *, follow_redirects: bool = True) -> dict[str, Any]:
    name, url = item
    started = time.monotonic()
    hostname = urllib.parse.urlsplit(url).hostname
    resolved_ip = None
    if hostname:
        try:
            addresses = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            resolved_ip = str(addresses[0][4][0]) if addresses else None
        except OSError:
            pass
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"Mozilla/5.0 (compatible; ServerSuitabilityAudit/{VERSION})",
            "Accept": "application/dns-json,application/json,text/html,*/*",
        },
    )
    try:
        opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=8) as response:
            code = response.status
            final_url = response.url
            response.read(1024)
        error = None
    except urllib.error.HTTPError as exc:
        code = exc.code
        final_url = exc.url
        redirect_url = exc.headers.get("Location") if exc.headers else None
        error = str(exc)
    except (OSError, urllib.error.URLError) as exc:
        return {
            "name": name,
            "url": url,
            "reachable": False,
            "status_code": None,
            "ip": resolved_ip,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": str(exc),
        }
    return {
        "name": name,
        "url": url,
        "reachable": True,
        "status_code": code,
        "ip": resolved_ip,
        "final_url": final_url,
        "redirect_url": locals().get("redirect_url"),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "access_denied": code in {403, 451},
        "error": error,
    }


def _check_access_target(item: tuple[str, str]) -> dict[str, Any]:
    name, https_url = item
    parsed = urllib.parse.urlsplit(https_url)
    http_url = urllib.parse.urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, ""))
    http = _check_url((name, http_url), follow_redirects=False)
    https = _check_url((name, https_url))
    return {
        **https,
        "name": name,
        "domain": parsed.hostname or name,
        "ip": https.get("ip") or http.get("ip"),
        "http": http,
        "https": https,
    }


def run_access_checks() -> TestResult:
    _stage_output("\n▶ Доступность сервисов и геоограничения")
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        checks = list(executor.map(_check_access_target, ACCESS_TARGETS))
    failed = [item["name"] for item in checks if not item["reachable"]]
    denied = [item["name"] for item in checks if item.get("access_denied")]
    if checks and len(failed) >= max(3, math.ceil(len(checks) / 2)):
        status = "bad"
    elif failed:
        status = "warning"
    elif denied:
        status = "warning"
    else:
        status = "ok"
    summary = f"ответили {len(checks) - len(failed)}/{len(checks)}"
    if failed:
        summary += f", нет соединения: {', '.join(failed)}"
    if denied:
        summary += f", HTTP 403/451: {', '.join(denied)}"
    output = "\n".join(
        f"{item['name']}: {item.get('status_code') or 'FAIL'}; {item['elapsed_ms']} ms; "
        f"{item.get('error') or item.get('final_url', '')}"
        for item in checks
    )
    _stage_output(f"  {summary}", summary)
    return TestResult(
        name="Доступность сервисов и геоограничения",
        category="access",
        status=status,
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics={
            "checks": checks,
            "reachable": len(checks) - len(failed),
            "failed": failed,
            "access_denied": denied,
            "limitations": (
                "HTTP-ответ доказывает доступность с этого IP сейчас, но не определяет причину "
                "403 и не заменяет тест из реальной клиентской сети."
            ),
        },
        output=output,
    )


def _dns_query_packet(domain: str, transaction_id: int) -> bytes:
    labels = domain.rstrip(".").encode("idna").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError(f"Некорректное DNS-имя: {domain!r}")
    question = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
    return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)


def _dns_skip_name(message: bytes, offset: int) -> int:
    while True:
        if offset >= len(message):
            raise ValueError("обрезанное DNS-имя")
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("обрезанный DNS-указатель")
            return offset + 2
        if length & 0xC0:
            raise ValueError("неизвестный формат DNS-имени")
        offset += length + 1


def _parse_dns_response(message: bytes, transaction_id: int) -> dict[str, Any]:
    if len(message) < 12:
        raise ValueError("слишком короткий DNS-ответ")
    response_id, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", message[:12])
    if response_id != transaction_id:
        raise ValueError("ID DNS-ответа не совпадает с запросом")
    if not flags & 0x8000:
        raise ValueError("получен не DNS-ответ")
    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"DNS вернул RCODE {rcode}")
    offset = 12
    for _ in range(questions):
        offset = _dns_skip_name(message, offset) + 4
        if offset > len(message):
            raise ValueError("обрезанный DNS-вопрос")
    addresses: list[str] = []
    for _ in range(answers):
        offset = _dns_skip_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("обрезанная DNS-запись")
        record_type, record_class, _, length = struct.unpack("!HHIH", message[offset : offset + 10])
        offset += 10
        data = message[offset : offset + length]
        if len(data) != length:
            raise ValueError("обрезанные данные DNS-записи")
        if record_type == 1 and record_class == 1 and length == 4:
            addresses.append(socket.inet_ntoa(data))
        offset += length
    if not answers:
        raise ValueError("DNS-ответ не содержит записей")
    return {"rcode": rcode, "answer_count": answers, "addresses": sorted(set(addresses))}


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise OSError("соединение закрылось до полного DNS-ответа")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _dns_transport_probe(
    server_ip: str,
    server_name: str,
    doh_url: str,
    transport: str,
    *,
    domain: str = "example.com",
    timeout: float = 3.0,
) -> dict[str, Any]:
    if transport == "doh" and server_name.endswith(".quad9.net"):
        return {
            "available": None,
            "supported": False,
            "elapsed_ms": 0.0,
            "error": "Quad9 DoH требует HTTP/2; стандартный HTTP-клиент Python его не поддерживает",
        }
    transaction_id = int.from_bytes(os.urandom(2), "big")
    packet = _dns_query_packet(domain, transaction_id)
    started = time.monotonic()
    try:
        if transport == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.settimeout(timeout)
                connection.connect((server_ip, 53))
                connection.send(packet)
                response = connection.recv(4096)
        elif transport == "tcp":
            with socket.create_connection((server_ip, 53), timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall(struct.pack("!H", len(packet)) + packet)
                length = struct.unpack("!H", _recv_exact(connection, 2))[0]
                response = _recv_exact(connection, length)
        elif transport == "dot":
            context = ssl.create_default_context()
            with socket.create_connection((server_ip, 853), timeout=timeout) as raw:
                raw.settimeout(timeout)
                with context.wrap_socket(raw, server_hostname=server_name) as connection:
                    connection.sendall(struct.pack("!H", len(packet)) + packet)
                    length = struct.unpack("!H", _recv_exact(connection, 2))[0]
                    response = _recv_exact(connection, length)
        elif transport == "doh":
            encoded = base64.urlsafe_b64encode(packet).rstrip(b"=").decode("ascii")
            separator = "&" if "?" in doh_url else "?"
            request = urllib.request.Request(
                f"{doh_url}{separator}dns={encoded}",
                headers={"Accept": "application/dns-message", "User-Agent": f"ServerSuitabilityAudit/{VERSION}"},
            )
            with urllib.request.urlopen(request, timeout=timeout + 2) as http_response:
                response = http_response.read(65535)
        else:
            raise ValueError(f"Неизвестный DNS-транспорт: {transport}")
        parsed = _parse_dns_response(response, transaction_id)
        return {
            "available": True,
            "supported": True,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            **parsed,
        }
    except (OSError, ValueError, ssl.SSLError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        return {
            "available": False,
            "supported": True,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": str(exc),
        }


def _check_dns_resolver(item: tuple[str, str, str, str]) -> dict[str, Any]:
    name, address, server_name, doh_url = item
    transport_names = ("udp", "tcp", "dot", "doh")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(transport_names)) as executor:
        probes = list(
            executor.map(
                lambda transport: _dns_transport_probe(address, server_name, doh_url, transport),
                transport_names,
            )
        )
    transports = dict(zip(transport_names, probes, strict=True))
    return {"name": name, "address": address, "transports": transports}


def run_dns_checks() -> TestResult:
    _stage_output("\n▶ DNS: Cloudflare, Google, Quad9 и Yandex")
    started = time.monotonic()
    system_started = time.monotonic()
    try:
        system_addresses = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo("example.com", 443, socket.AF_INET, socket.SOCK_STREAM)
            }
        )
        system_dns = {
            "available": True,
            "elapsed_ms": round((time.monotonic() - system_started) * 1000, 1),
            "addresses": system_addresses,
        }
    except OSError as exc:
        system_dns = {
            "available": False,
            "elapsed_ms": round((time.monotonic() - system_started) * 1000, 1),
            "error": str(exc),
        }
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DNS_RESOLVERS)) as executor:
        resolvers = list(executor.map(_check_dns_resolver, DNS_RESOLVERS))
    working = [
        item for item in resolvers if any(probe.get("available") for probe in item["transports"].values())
    ]
    fully_working = [
        item for item in resolvers if all(probe.get("available") for probe in item["transports"].values())
    ]
    standard_working = [
        item
        for item in resolvers
        if any(item["transports"][key].get("available") for key in ("udp", "tcp"))
    ]
    encrypted_working = [
        item
        for item in resolvers
        if any(item["transports"][key].get("available") for key in ("dot", "doh"))
    ]
    if not system_dns["available"] and not working:
        status = "bad"
    elif len(standard_working) < len(resolvers) or len(encrypted_working) < len(resolvers):
        status = "warning"
    else:
        status = "ok"
    summary = (
        f"обычный DNS {len(standard_working)}/{len(resolvers)}, "
        f"защищённый DNS {len(encrypted_working)}/{len(resolvers)}"
    )
    output_lines = []
    for resolver in resolvers:
        states = ", ".join(
            f"{transport.upper()}={'OK' if probe.get('available') else 'FAIL'}"
            for transport, probe in resolver["transports"].items()
        )
        output_lines.append(f"{resolver['name']} {resolver['address']}: {states}")
    _stage_output(f"  {summary}", summary)
    return TestResult(
        name="DNS-резолверы и защищённый DNS",
        category="dnscheck",
        status=status,
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics={
            "test_domain": "example.com",
            "system_dns": system_dns,
            "resolvers": resolvers,
            "working_resolvers": len(working),
            "fully_working_resolvers": len(fully_working),
            "standard_working_resolvers": len(standard_working),
            "encrypted_working_resolvers": len(encrypted_working),
            "limitations": (
                "Тест подтверждает ответы конкретных резолверов и транспортов. "
                "Он не объявляет разные CDN-адреса подменой DNS без дополнительных доказательств."
            ),
        },
        output="\n".join(output_lines),
    )


def _check_dpi_target(item: tuple[str, str]) -> dict[str, Any]:
    name, domain_path = item
    return {
        "name": name,
        "domain": domain_path.split("/", 1)[0],
        "http": _check_url((name, f"http://{domain_path}"), follow_redirects=False),
        "https": _check_url((name, f"https://{domain_path}")),
    }


def run_dpi_checks() -> TestResult:
    _stage_output("\n▶ Признаки цензуры/DPI — профиль для серверов РФ")
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        checks = list(executor.map(_check_dpi_target, DPI_TARGETS))
    https_failed = [item["name"] for item in checks if not item["https"].get("reachable")]
    both_failed = [
        item["name"]
        for item in checks
        if not item["http"].get("reachable") and not item["https"].get("reachable")
    ]
    if len(https_failed) >= max(4, math.ceil(len(checks) / 2)):
        status = "bad"
    elif https_failed:
        status = "warning"
    else:
        status = "ok"
    summary = f"HTTPS отвечает у {len(checks) - len(https_failed)}/{len(checks)} целей"
    if https_failed:
        summary += f"; признаки фильтрации: {', '.join(https_failed)}"
    output = "\n".join(
        f"{item['name']}: HTTP {item['http'].get('status_code') or 'FAIL'}; "
        f"HTTPS {item['https'].get('status_code') or 'FAIL'}"
        for item in checks
    )
    _stage_output(f"  {summary}", summary)
    return TestResult(
        name="Признаки цензуры и DPI (профиль РФ)",
        category="dpi",
        status=status,
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics={
            "checks": checks,
            "https_failed": https_failed,
            "both_failed": both_failed,
            "source_profile": "https://github.com/vernette/censorcheck",
            "limitations": (
                "Тайм-аут или сброс соединения является признаком, но не доказательством DPI: "
                "причиной также могут быть DNS, маршрут, firewall или защита самого сайта."
            ),
        },
        output=output,
    )


def run_disk_benchmark(size_mib: int = 256) -> TestResult:
    _stage_output(f"\n▶ Последовательный disk I/O ({size_mib} MiB)")
    started = time.monotonic()
    block = b"\0" * (1024 * 1024)
    path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="vpn-audit-", delete=False) as handle:
            path = handle.name
            write_started = time.monotonic()
            for _ in range(size_mib):
                handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())
            write_seconds = time.monotonic() - write_started
        read_started = time.monotonic()
        bytes_read = 0
        with open(path, "rb", buffering=0) as handle:
            while chunk := handle.read(len(block)):
                bytes_read += len(chunk)
        read_seconds = time.monotonic() - read_started
        write_mbps = size_mib / write_seconds
        read_mbps = (bytes_read / 1024 / 1024) / read_seconds
        status = "ok" if write_mbps >= 100 else "warning" if write_mbps >= 40 else "bad"
        summary = f"write+fsync {write_mbps:.1f} MiB/s, cached/read {read_mbps:.1f} MiB/s"
        metrics = {
            "size_mib": size_mib,
            "write_fsync_mib_s": round(write_mbps, 2),
            "read_mib_s": round(read_mbps, 2),
            "warning": "Короткий последовательный тест; чтение может обслуживаться page cache.",
        }
    except OSError as exc:
        status = "failed"
        summary = f"Ошибка disk I/O: {exc}"
        metrics = {"size_mib": size_mib, "error": str(exc)}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    _stage_output(f"  {summary}", summary)
    return TestResult(
        name=f"Последовательный disk I/O ({size_mib} MiB)",
        category="disk",
        status=status,
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics=metrics,
    )


def _read_text(path: str) -> str:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _sysctl_value(text: str, *names: str) -> str | None:
    for name in names:
        match = re.search(
            rf"^{re.escape(name)}\s*(?:=|:)\s*(\S+)\s*$",
            text,
            re.MULTILINE,
        )
        if match:
            return match.group(1).strip()
    return None


def _first_positive_integer_file(paths: tuple[str, ...], *, allow_zero: bool) -> tuple[str | None, str | None]:
    for path in paths:
        value = _read_text(path).strip()
        if not re.fullmatch(r"\d+", value):
            continue
        if allow_zero or int(value) > 0:
            return value, path
    return None, None


def _conntrack_metrics(sysctl_text: str) -> dict[str, Any]:
    count = _sysctl_value(
        sysctl_text,
        "net.netfilter.nf_conntrack_count",
        "net.ipv4.netfilter.ip_conntrack_count",
    )
    maximum = _sysctl_value(
        sysctl_text,
        "net.netfilter.nf_conntrack_max",
        "net.ipv4.netfilter.ip_conntrack_max",
    )
    sources: list[str] = []
    if count is not None or maximum is not None:
        sources.append("sysctl")
    if count is None:
        count, source = _first_positive_integer_file(
            (
                "/proc/sys/net/netfilter/nf_conntrack_count",
                "/proc/sys/net/ipv4/netfilter/ip_conntrack_count",
            ),
            allow_zero=True,
        )
        if source:
            sources.append("procfs")
    if maximum is None:
        maximum, source = _first_positive_integer_file(
            (
                "/proc/sys/net/netfilter/nf_conntrack_max",
                "/proc/sys/net/ipv4/netfilter/ip_conntrack_max",
            ),
            allow_zero=False,
        )
        if source:
            sources.append("procfs")

    utilization = None
    if count is not None and maximum is not None and int(maximum) > 0:
        utilization = round(int(count) / int(maximum) * 100, 2)
    if count is None or maximum is None:
        note = (
            "счётчики ядра недоступны: nf_conntrack может быть не загружен, "
            "не использоваться или быть скрыт контейнером/провайдером"
        )
    else:
        note = None
    return {
        "nf_conntrack_count": count,
        "nf_conntrack_max": maximum,
        "nf_conntrack_utilization_percent": utilization,
        "nf_conntrack_source": "+".join(dict.fromkeys(sources)) or None,
        "nf_conntrack_note": note,
    }


def _public_ip(version: int) -> str | None:
    url = "https://api6.ipify.org" if version == 6 else "https://api4.ipify.org"
    family = socket.AF_INET6 if version == 6 else socket.AF_INET
    original_getaddrinfo = socket.getaddrinfo

    def family_getaddrinfo(*args: Any, **kwargs: Any) -> Any:
        responses = original_getaddrinfo(*args, **kwargs)
        return [item for item in responses if item[0] == family]

    try:
        socket.getaddrinfo = family_getaddrinfo  # type: ignore[assignment]
        request = urllib.request.Request(url, headers={"User-Agent": f"server-suitability-audit/{VERSION}"})
        with urllib.request.urlopen(request, timeout=5) as response:
            value = response.read(100).decode().strip()
            ipaddress.ip_address(value)
            return value
    except (OSError, ValueError, urllib.error.URLError):
        return None
    finally:
        socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]


def _memory_metrics() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in _read_text("/proc/meminfo").splitlines():
        match = re.match(r"(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)\s+kB", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    return values


def _cpu_metrics() -> dict[str, Any]:
    cpuinfo = _read_text("/proc/cpuinfo")
    models = re.findall(r"^model name\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
    flags_match = re.search(r"^flags\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
    return {
        "logical_cpus": os.cpu_count(),
        "model": models[0].strip() if models else platform.processor() or None,
        "aes_flag": bool(flags_match and "aes" in flags_match.group(1).split()),
    }


def _parse_vmstat_steal(output: str) -> float | None:
    rows = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 17 and all(re.fullmatch(r"-?[\d.]+", field) for field in fields):
            rows.append(fields)
    if len(rows) > 1:
        return round(statistics.mean(float(row[-1]) for row in rows[1:]), 2)
    return None


def system_inventory(runner: CommandRunner, benchmark: bool = True) -> list[TestResult]:
    _stage_output("\n▶ Система и сетевой стек")
    started = time.monotonic()
    memory = _memory_metrics()
    cpu = _cpu_metrics()
    root_usage = shutil.disk_usage("/")
    metrics: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        **cpu,
        **{key.lower() + "_bytes": value for key, value in memory.items()},
        "root_disk_total_bytes": root_usage.total,
        "root_disk_free_bytes": root_usage.free,
        "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        "public_ipv4": _public_ip(4),
        "public_ipv6": _public_ip(6),
    }
    commands = [
        (["systemd-detect-virt"], "virtualization"),
        (["ip", "-brief", "address"], "addresses"),
        (["ip", "route"], "ipv4_routes"),
        (["ip", "-6", "route"], "ipv6_routes"),
        (["ip", "-s", "link"], "link_counters"),
        (["ss", "-s"], "socket_summary"),
        (
            [
                "sysctl",
                "-e",
                "net.ipv4.tcp_congestion_control",
                "net.core.default_qdisc",
                "net.core.rmem_max",
                "net.core.wmem_max",
                "net.ipv4.tcp_rmem",
                "net.ipv4.tcp_wmem",
                "net.netfilter.nf_conntrack_count",
                "net.netfilter.nf_conntrack_max",
                "net.ipv4.ip_local_port_range",
            ],
            "network_sysctl",
        ),
        (["timedatectl", "show", "--property=NTPSynchronized", "--value"], "ntp_synchronized"),
    ]
    raw_sections: list[str] = []
    for args, key in commands:
        item = runner.run(f"Инвентаризация: {key}", "system-detail", args, timeout=10, env=_base_environment())
        value = item.output.strip()
        if item.status == "ok" or (key == "network_sysctl" and value):
            metrics[key] = value
            raw_sections.append(f"$ {item.command}\n{value}")
        else:
            metrics[key] = None
    sysctl_text = str(metrics.get("network_sysctl") or "")
    for source, destination in (
        ("net.ipv4.tcp_congestion_control", "tcp_congestion_control"),
        ("net.core.default_qdisc", "default_qdisc"),
    ):
        metrics[destination] = _sysctl_value(sysctl_text, source)
    metrics.update(_conntrack_metrics(sysctl_text))
    summary = (
        f"{cpu.get('logical_cpus') or '?'} vCPU, "
        f"RAM {_human_bytes(memory.get('MemTotal', 0))}, "
        f"IPv4 {metrics['public_ipv4'] or 'не определён'}, "
        f"IPv6 {metrics['public_ipv6'] or 'нет/не определён'}"
    )
    inventory = TestResult(
        name="Система и сетевой стек",
        category="system",
        status="ok",
        summary=summary,
        elapsed_seconds=round(time.monotonic() - started, 3),
        metrics=metrics,
        output="\n\n".join(raw_sections),
    )
    results = [inventory]

    vmstat = runner.run(
        "CPU steal/iowait (5 секунд)",
        "system",
        ["vmstat", "1", "6"],
        timeout=10,
        env=_base_environment(),
    )
    steal = _parse_vmstat_steal(vmstat.output)
    if steal is not None:
        vmstat.metrics["steal_avg_percent"] = steal
        vmstat.status = "ok" if steal < 2 else "warning" if steal < 5 else "bad"
        vmstat.summary = f"Средний steal: {steal:g}% (без прикладной нагрузки)"
    results.append(vmstat)

    if benchmark:
        for cipher, label in (("aes-256-gcm", "AES-256-GCM"), ("chacha20-poly1305", "ChaCha20-Poly1305")):
            item = runner.run(
                f"OpenSSL {label} benchmark",
                "crypto",
                [
                    "openssl",
                    "speed",
                    "-elapsed",
                    "-seconds",
                    "3",
                    "-bytes",
                    "16384",
                    "-evp",
                    cipher,
                    "-mr",
                ],
                timeout=10,
                env=_base_environment(),
            )
            results.append(_finalize_crypto_benchmark(item))
    return results


def _is_ipv6(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).version == 6
    except ValueError:
        return False


def _human_bytes(value: int | float) -> str:
    size = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or suffix == "TiB":
            return f"{size:.1f} {suffix}"
        size /= 1024
    return f"{size:.1f} TiB"


def _piecewise_lower_better(value: float, points: list[tuple[float, float]]) -> float:
    for limit, score in points:
        if value <= limit:
            return score
    return points[-1][1]


def _throughput_score(mbps: float, expected: float) -> float:
    ratio = mbps / max(expected, 1)
    points = [(0.1, 10), (0.25, 30), (0.5, 55), (0.75, 75), (1.0, 90), (1.5, 100)]
    previous_ratio, previous_score = 0.0, 0.0
    for current_ratio, current_score in points:
        if ratio <= current_ratio:
            share = (ratio - previous_ratio) / (current_ratio - previous_ratio)
            return previous_score + share * (current_score - previous_score)
        previous_ratio, previous_score = current_ratio, current_score
    return 100.0


def _automatic_throughput_score(mbps: float) -> float:
    """Score measured VPN-path throughput without pretending to know the tariff.

    The bands are deliberately broad. They describe practical server classes,
    not a guaranteed number of customers or the nominal speed of a VPS NIC.
    """
    points = [
        (0.0, 0.0),
        (25.0, 15.0),
        (50.0, 30.0),
        (100.0, 50.0),
        (200.0, 70.0),
        (300.0, 80.0),
        (500.0, 90.0),
        (1_000.0, 100.0),
    ]
    value = max(0.0, mbps)
    for index in range(1, len(points)):
        lower_speed, lower_score = points[index - 1]
        upper_speed, upper_score = points[index]
        if value <= upper_speed:
            share = (value - lower_speed) / (upper_speed - lower_speed)
            return lower_score + share * (upper_score - lower_score)
    return 100.0


def _effective_throughput_score(mbps: float, expected_mbps: int | None) -> float:
    if expected_mbps and expected_mbps > 0:
        return _throughput_score(mbps, expected_mbps)
    return _automatic_throughput_score(mbps)


def _preferred_iperf_profile(
    measurements: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Use the 4-stream profile for capacity/scoring when both profiles exist."""
    four_stream = [item for item in measurements if item.get("streams") == 4]
    return four_stream or measurements


def _iperf_measurements_are_public(measurements: list[dict[str, Any]]) -> bool:
    selected = _preferred_iperf_profile(measurements)
    return bool(selected) and all(
        isinstance(item.get("endpoint"), dict) and item["endpoint"].get("public")
        for item in selected
    )


def _representative_iperf_speed(measurements: list[dict[str, Any]]) -> float | None:
    """Return the weaker direction, using public-server medians when possible."""
    comparable = [
        item
        for item in _preferred_iperf_profile(measurements)
        if isinstance(item.get("mbps"), (int, float))
    ]
    if not comparable:
        return None
    public = [
        item
        for item in comparable
        if isinstance(item.get("endpoint"), dict) and item["endpoint"].get("public")
    ]
    selected = public or comparable
    direction_medians: list[float] = []
    for direction in ("upload", "download"):
        values = [
            float(item["mbps"])
            for item in selected
            if item.get("direction") == direction
        ]
        if values:
            direction_medians.append(statistics.median(values))
    if direction_medians:
        return min(direction_medians)
    return min(float(item["mbps"]) for item in selected)


def _vpn_capacity_estimate(mbps: float, reserve_percent: int = 30) -> dict[str, Any]:
    """Estimate simultaneous active traffic consumers, not total VPN accounts."""
    usable_mbps = max(0.0, mbps) * (100 - reserve_percent) / 100
    return {
        "measured_mbps": round(max(0.0, mbps), 1),
        "usable_mbps": round(usable_mbps, 1),
        "reserve_percent": reserve_percent,
        "active_users": {
            per_user: math.floor(usable_mbps / per_user)
            for per_user in (10, 25, 50)
        },
    }


def _automatic_speed_description(mbps: float) -> str:
    if mbps >= 1_000:
        return "отличный канал для крупной VPN-ноды"
    if mbps >= 500:
        return "очень хороший канал для VPN-ноды"
    if mbps >= 300:
        return "хороший канал для обычной VPN-ноды"
    if mbps >= 100:
        return "достаточно для небольшой или средней VPN-ноды"
    if mbps >= 50:
        return "подойдёт только для небольшой нагрузки"
    return "слишком мало для комфортной многопользовательской VPN-ноды"


def _iperf_retransmission_status(retransmits_per_gib: float | None) -> str:
    """Return a human status for a comparable, volume-normalized TCP metric.

    iperf3 and the kernel do not define universal pass/fail limits.  These
    deliberately broad operational bands flag paths that deserve a repeat
    test without pretending that Retr is an exact packet-loss percentage.
    """
    if retransmits_per_gib is None:
        return "ИЗМЕРЕНО"
    if retransmits_per_gib <= 500:
        return "ХОРОШО"
    if retransmits_per_gib <= 5_000:
        return "ВНИМАНИЕ"
    return "ПЛОХО"


def _iperf_retransmission_score(retransmits_per_gib: float) -> float:
    return _piecewise_lower_better(
        retransmits_per_gib,
        [
            (100, 100),
            (500, 95),
            (1_000, 85),
            (5_000, 65),
            (20_000, 35),
            (100_000, 10),
            (math.inf, 0),
        ],
    )


def _representative_iperf_retransmits_per_gib(
    measurements: list[dict[str, Any]],
) -> float | None:
    comparable = [
        item
        for item in _preferred_iperf_profile(measurements)
        if isinstance(item.get("retransmits_per_gib"), (int, float))
    ]
    if not comparable:
        return None
    public = [
        item
        for item in comparable
        if isinstance(item.get("endpoint"), dict) and item["endpoint"].get("public")
    ]
    selected = public or comparable
    direction_medians: list[float] = []
    for direction in ("upload", "download"):
        values = [
            float(item["retransmits_per_gib"])
            for item in selected
            if item.get("direction") == direction
        ]
        if values:
            direction_medians.append(statistics.median(values))
    if direction_medians:
        return max(direction_medians)
    return statistics.median(float(item["retransmits_per_gib"]) for item in selected)


def calculate_score(
    results: list[TestResult],
    role: str,
    expected_mbps: int,
    requested_tests: set[str] | None = None,
) -> dict[str, Any]:
    # `role` remains in the call signature for compatibility with 1.x callers.
    # Scoring is now one balanced server/VPN profile for everyone.
    _ = role
    pings = [
        result.metrics
        for result in results
        if result.category in {"ping", "soak"} and "loss_percent" in result.metrics
    ]
    iperfs = [
        result.metrics
        for result in results
        if result.category in {"iperf", "soak_iperf"} and "mbps" in result.metrics
    ]
    udp_results = [
        result.metrics
        for result in results
        if result.category == "udp" and "loss_percent" in result.metrics
    ]
    vmstats = [result.metrics for result in results if "steal_avg_percent" in result.metrics]
    conntrack_stats = [
        result.metrics
        for result in results
        if isinstance(result.metrics.get("nf_conntrack_utilization_percent"), (int, float))
    ]
    crypto = [
        result.metrics
        for result in results
        if result.category == "crypto"
        and (
            isinstance(result.metrics.get("throughput_mbps"), (int, float))
            or isinstance(result.metrics.get("estimated_gbps"), (int, float))
        )
    ]

    dimensions: dict[str, float] = {}
    timed_pings = [item for item in pings if "avg_ms" in item]
    if timed_pings:
        worst_avg = max(float(item["avg_ms"]) for item in timed_pings)
        dimensions["latency"] = _piecewise_lower_better(
            worst_avg, [(20, 100), (40, 90), (70, 75), (110, 55), (160, 30), (250, 10), (math.inf, 0)]
        )
    stability_pings = [
        item
        for item in pings
        if "transmitted" not in item or int(item.get("transmitted", 0)) >= 5
    ]
    stability_samples = [*stability_pings, *udp_results]
    if stability_samples:
        worst_loss = max(float(item.get("loss_percent", 0)) for item in stability_samples)
        worst_jitter = max(float(item.get("jitter_ms", 0)) for item in stability_samples)
        if worst_loss >= 100:
            # With no received packets there is no meaningful jitter sample.
            dimensions["stability"] = 0.0
        else:
            loss_score = _piecewise_lower_better(
                worst_loss, [(0, 100), (0.1, 90), (0.5, 70), (1, 45), (2, 20), (5, 5), (math.inf, 0)]
            )
            jitter_score = _piecewise_lower_better(
                worst_jitter, [(2, 100), (5, 85), (10, 65), (20, 35), (40, 10), (math.inf, 0)]
            )
            dimensions["stability"] = round(loss_score * 0.7 + jitter_score * 0.3, 1)
    if iperfs:
        weakest_direction = _representative_iperf_speed(iperfs)
        assert weakest_direction is not None
        speed_score = _effective_throughput_score(weakest_direction, expected_mbps)
        representative_retransmits = _representative_iperf_retransmits_per_gib(iperfs)
        if representative_retransmits is None:
            dimensions["throughput"] = round(speed_score, 1)
        else:
            retransmission_score = _iperf_retransmission_score(representative_retransmits)
            retransmission_weight = 0.1 if _iperf_measurements_are_public(iperfs) else 0.3
            dimensions["throughput"] = round(
                speed_score * (1 - retransmission_weight)
                + retransmission_score * retransmission_weight,
                1,
            )
    system_parts: list[float] = []
    if vmstats:
        steal = max(float(item["steal_avg_percent"]) for item in vmstats)
        system_parts.append(
            _piecewise_lower_better(steal, [(0.5, 100), (1, 90), (2, 75), (5, 40), (10, 10), (math.inf, 0)])
        )
    if conntrack_stats:
        utilization = max(
            float(item["nf_conntrack_utilization_percent"])
            for item in conntrack_stats
        )
        system_parts.append(
            _piecewise_lower_better(
                utilization,
                [(50, 100), (70, 90), (85, 60), (95, 20), (100, 0), (math.inf, 0)],
            )
        )
    if crypto:
        weakest_crypto_mbps = min(
            float(item["throughput_mbps"])
            if isinstance(item.get("throughput_mbps"), (int, float))
            else float(item["estimated_gbps"]) * 1000
            for item in crypto
        )
        system_parts.append(_crypto_benchmark_score(weakest_crypto_mbps))
    if system_parts:
        dimensions["system"] = round(statistics.mean(system_parts), 1)

    weights = {"latency": 30, "stability": 25, "throughput": 35, "system": 10}
    available_weight = sum(weights[key] for key in dimensions)
    score = (
        round(sum(dimensions[key] * weights[key] for key in dimensions) / available_weight)
        if available_weight
        else None
    )
    measured = {
        "ping": bool(pings),
        "iperf_bidirectional": len(iperfs) >= 2,
        "udp_bidirectional": len(udp_results) >= 2,
        "system": bool(system_parts),
    }
    tcp_results = [result for result in results if result.category == "tcp"]
    all_ping_unreachable = bool(pings) and all(
        float(item.get("loss_percent", 0)) >= 100 for item in pings
    )
    all_tcp_unreachable = bool(tcp_results) and all(
        int(result.metrics.get("successful_connections", 0)) == 0 for result in tcp_results
    )
    if measured["ping"] and measured["iperf_bidirectional"] and measured["system"]:
        confidence = "высокая"
    elif measured["ping"] and measured["iperf_bidirectional"]:
        confidence = "средняя"
    else:
        confidence = "низкая"
    if all_ping_unreachable and all_tcp_unreachable:
        ports = sorted(
            {
                int(result.metrics["port"])
                for result in tcp_results
                if "port" in result.metrics
            }
        )
        port_text = "/".join(map(str, ports)) or "выбранном порту"
        verdict = f"цель не отвечает на ICMP и TCP/{port_text} с этой машины"
    elif requested_tests == {"ping"} and all_ping_unreachable:
        verdict = "цель не отвечает на ICMP; проверьте TCP и маршрут"
    elif score is None or confidence == "низкая":
        verdict = "недостаточно данных"
    elif score >= 90:
        verdict = "отличный кандидат"
    elif score >= 75:
        verdict = "хороший кандидат"
    elif score >= 60:
        verdict = "условно подходит"
    elif score >= 40:
        verdict = "есть заметные риски"
    else:
        verdict = "плохой кандидат"

    warnings: list[str] = []
    has_four_stream_iperf = any(
        result.category == "iperf" and result.metrics.get("streams") == 4
        for result in results
    )
    for result in results:
        if result.category in {"ping", "soak"} and float(result.metrics.get("loss_percent", 0)) > 0:
            warnings.append(f"{result.name}: обнаружены потери пакетов")
        if result.category == "ping" and int(result.metrics.get("transmitted", 0)) == 1:
            warnings.append(
                f"{result.name}: один запрос показывает задержку только в этот момент; "
                "для оценки стабильности используйте 200"
            )
        if float(result.metrics.get("steal_avg_percent", 0)) >= 2:
            warnings.append("CPU steal ≥ 2%: VPS может быть перепродан или соседние VM создают помехи")
        if result.category == "crypto" and result.status in {"warning", "bad", "failed"}:
            warnings.append(f"{result.name}: {result.summary}")
        conntrack_utilization = result.metrics.get("nf_conntrack_utilization_percent")
        if isinstance(conntrack_utilization, (int, float)) and float(conntrack_utilization) >= 70:
            warnings.append(
                f"Conntrack заполнен на {float(conntrack_utilization):g}%: "
                "при достижении лимита новые соединения начнут теряться"
            )
        if result.category in {"ipinfo", "access", "dpi", "dnscheck"} and result.status in {"warning", "bad"}:
            warnings.append(result.summary)
        if result.category == "tcp" and result.status == "failed":
            warnings.append(f"{result.name}: соединение не установлено; порт может быть закрыт или фильтроваться")
        normalized_retransmits = result.metrics.get("retransmits_per_gib")
        if result.category in {"iperf", "soak_iperf"} and isinstance(
            normalized_retransmits, (int, float)
        ):
            if (
                result.category == "iperf"
                and has_four_stream_iperf
                and result.metrics.get("streams") != 4
            ):
                continue
            retransmission_status = _iperf_retransmission_status(float(normalized_retransmits))
            if retransmission_status in {"ВНИМАНИЕ", "ПЛОХО"}:
                endpoint = result.metrics.get("endpoint")
                endpoint_name = (
                    ", ".join(
                        str(value)
                        for value in (endpoint.get("city"), endpoint.get("name"))
                        if value
                    )
                    if isinstance(endpoint, dict)
                    else result.name
                )
                is_public = isinstance(endpoint, dict) and endpoint.get("public")
                if is_public:
                    reason = (
                        "публичная точка могла быть перегружена; это слабый сигнал, "
                        "повторите тест позже"
                    )
                elif retransmission_status == "ПЛОХО":
                    reason = (
                        "слишком много; возможны потери, перегрузка или "
                        "нестабильный маршрут"
                    )
                else:
                    reason = "выше спокойного уровня; повторите измерение"
                warnings.append(
                    f"{endpoint_name}: TCP-повторы "
                    f"{float(normalized_retransmits):g}/ГиБ — {reason}"
                )
    if not measured["iperf_bidirectional"] and (
        requested_tests is None or bool(requested_tests & {"iperf", "udp"})
    ):
        warnings.append("Нет двустороннего iperf3: пропускная способность не подтверждена")
    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
        "dimensions": dimensions,
        "measured": measured,
        "weights": weights,
        "warnings": list(dict.fromkeys(warnings)),
        "expected_mbps": expected_mbps,
        "method": "Рейтинг эвристический; отсутствующие измерения не считаются нулём, а снижают уверенность.",
    }


def estimate_audit_units(config: AuditConfig) -> float:
    """Estimate relative stage duration; the live ETA self-corrects after each stage."""
    units = 0.0
    if "system" in config.tests:
        units += 24
    if "disk" in config.tests:
        units += 5
    if "ipinfo" in config.tests:
        units += 12
    if "access" in config.tests:
        units += 14
    if "dpi" in config.tests:
        units += 14
    if "dnscheck" in config.tests:
        units += 12
    per_target = {
        "ping": max(4.0, config.ping_count * (0.25 if os.name != "nt" else 1.0)),
        "tcp": 16.0,
        "mtr": max(10.0, DEFAULT_MTR_COUNT * 0.5),
        "traceroute": 12.0,
        "pmtu": 8.0,
    }
    units += len(config.targets) * sum(
        estimate for test, estimate in per_target.items() if test in config.tests
    )
    if "soak" in config.tests:
        units += len(config.targets) * config.soak_seconds
    if config.tests & {"iperf", "udp"}:
        endpoint_count = max(
            1,
            len({endpoint.city for endpoint in config.iperf_endpoints})
            if config.iperf_endpoints
            else 1,
        )
        tcp_units = endpoint_count * (
            7
            + (
                2 * len(IPERF_TCP_STREAM_PROFILES)
                if "iperf" in config.tests
                else 0
            )
            * (config.iperf_seconds + 2)
        )
        udp_units = (
            2 * (config.iperf_seconds + 2)
            if "udp" in config.tests and config.iperf_host
            else 0
        )
        units += tcp_units + udp_units
    return max(units, 1.0)


def run_audit(config: AuditConfig, *, verbose: bool = True) -> dict[str, Any]:
    global _ACTIVE_PROGRESS
    progress = ProgressTracker(estimate_audit_units(config), enabled=config.show_progress)
    _ACTIVE_PROGRESS = progress
    runner = CommandRunner(verbose=verbose, progress=progress)
    results: list[TestResult] = []
    started_at = dt.datetime.now(dt.timezone.utc)
    selected_names = ", ".join(sorted(config.tests))
    print(f"\nServer Suitability Audit {VERSION} | проверка {config.label}")
    print(f"Выбрано: {selected_names}")
    if requires_network_targets(config.tests) and config.targets:
        print(f"Цели обычных сетевых тестов: {', '.join(config.targets)}")
    if config.iperf_endpoints:
        cities = list(dict.fromkeys(endpoint.city for endpoint in config.iperf_endpoints))
        print(f"Отдельные iperf3-точки: {', '.join(cities)}")
    elif config.iperf_host:
        print(f"Отдельная iperf3-точка: {config.iperf_host}:{config.iperf_port}")
    if "iperf" in config.tests:
        if config.expected_mbps > 0:
            print(f"Ваш ручной ориентир скорости: {config.expected_mbps} Мбит/с")
        else:
            print("Оценка скорости: автоматическая; профили 1 и 4 TCP-потока")
    if "system" in config.tests:
        results.extend(
            progress.run("Система, CPU и сетевой стек", 24, lambda: system_inventory(runner, benchmark=True))
        )
    if "disk" in config.tests:
        results.append(progress.run("Короткий disk I/O", 5, run_disk_benchmark))
    if "ipinfo" in config.tests:
        results.append(
            progress.run("IP, геобазы и репутация", 12, lambda: run_ip_intelligence(config.check_ip))
        )
    if "access" in config.tests:
        results.append(progress.run("Сервисы и геоограничения", 14, run_access_checks))
    if "dpi" in config.tests:
        results.append(progress.run("Признаки цензуры/DPI", 14, run_dpi_checks))
    if "dnscheck" in config.tests:
        results.append(progress.run("DNS и защищённый DNS", 12, run_dns_checks))
    for target in config.targets:
        if "ping" in config.tests:
            units = max(4.0, config.ping_count * (0.25 if os.name != "nt" else 1.0))
            results.append(
                progress.run(
                    f"Ping → {target}", units, lambda target=target: run_ping(runner, target, config.ping_count)
                )
            )
        if "tcp" in config.tests:
            port_results = progress.run(
                f"TCP/UDP порт {config.tcp_port} → {target}",
                16,
                lambda target=target: [
                    run_tcp_probe(target, config.tcp_port),
                    run_udp_port_probe(target, config.tcp_port),
                ],
            )
            results.extend(port_results)
        if "mtr" in config.tests:
            results.append(
                progress.run(
                    f"MTR → {target}",
                    max(10.0, DEFAULT_MTR_COUNT * 0.5),
                    lambda target=target: run_mtr(runner, target, DEFAULT_MTR_COUNT),
                )
            )
        if "traceroute" in config.tests:
            results.append(
                progress.run(
                    f"Traceroute → {target}", 12, lambda target=target: run_traceroute(runner, target)
                )
            )
        if "pmtu" in config.tests:
            results.append(
                progress.run(f"Path MTU → {target}", 8, lambda target=target: run_pmtu(runner, target))
            )
        if "soak" in config.tests:
            results.extend(
                progress.run(
                    f"Длительный сетевой тест → {target}",
                    config.soak_seconds,
                    lambda target=target: run_network_soak(
                        runner,
                        target,
                        config.tcp_port,
                        config.soak_seconds,
                        config.soak_interval_seconds,
                        iperf_host=config.soak_iperf_host,
                        iperf_port=config.soak_iperf_port,
                        streams=config.iperf_streams,
                        expected_mbps=config.expected_mbps,
                    ),
                )
            )
    throughput_stage = bool(config.tests & {"iperf", "udp"})
    if throughput_stage:
        endpoint_count = max(
            1,
            len({endpoint.city for endpoint in config.iperf_endpoints})
            if config.iperf_endpoints
            else 1,
        )
        tcp_units = endpoint_count * (
            7
            + (
                2 * len(IPERF_TCP_STREAM_PROFILES)
                if "iperf" in config.tests
                else 0
            )
            * (config.iperf_seconds + 2)
        )
        udp_units = (
            2 * (config.iperf_seconds + 2)
            if "udp" in config.tests and config.iperf_host
            else 0
        )
        progress.begin(
            "iperf3: 1 и 4 TCP-потока, upload и download",
            tcp_units + udp_units,
        )
    if "iperf" in config.tests:
        if shutil.which("iperf3") is None:
            results.append(
                TestResult(
                    name="iperf3 TCP — тест скорости",
                    category="iperf",
                    status="skipped",
                    summary="Команда iperf3 не установлена; тест скорости не запускался",
                )
            )
        elif config.iperf_endpoints:
            _stage_output("\n▶ Поиск свободных портов публичных iperf3-серверов")
            available, unavailable_cities = resolve_available_by_city(config.iperf_endpoints)
            for endpoint, port in available:
                _stage_output(
                    f"  ✓ {endpoint.city}: {endpoint.host}:{port}",
                    f"iperf3 {endpoint.city}: upload/download",
                )
                results.extend(
                    run_iperf_endpoint(
                        runner,
                        endpoint,
                        port,
                        config.iperf_seconds,
                    )
                )
            for city in unavailable_cities:
                results.append(
                    TestResult(
                        name=f"iperf3 РФ [{city}]",
                        category="iperf",
                        status="skipped",
                        summary="Все endpoint/порты заняты или недоступны",
                    )
                )
        elif config.iperf_host:
            endpoint = IperfEndpoint(
                name="Собственный сервер",
                city="custom",
                host=config.iperf_host,
                ports=(config.iperf_port,),
                public=False,
                supports_udp=True,
                source="user",
            )
            results.extend(
                run_iperf_endpoint(
                    runner,
                    endpoint,
                    config.iperf_port,
                    config.iperf_seconds,
                    include_udp="udp" in config.tests,
                    udp_mbps=config.udp_mbps,
                )
            )
        else:
            results.append(
                TestResult(
                    name="iperf3 TCP",
                    category="iperf",
                    status="skipped",
                    summary="Не выбран публичный профиль и не задан --iperf-server",
                )
            )
    if "udp" in config.tests:
        if shutil.which("iperf3") is None:
            results.append(
                TestResult(
                    name="iperf3 UDP — тест стабильности",
                    category="udp",
                    status="skipped",
                    summary="Команда iperf3 не установлена; UDP-тест не запускался",
                )
            )
        elif config.iperf_host and config.iperf_endpoints:
            endpoint = IperfEndpoint(
                name="Собственный сервер",
                city="custom",
                host=config.iperf_host,
                ports=(config.iperf_port,),
                public=False,
                supports_udp=True,
                source="user",
            )
            udp_results = run_iperf_endpoint(
                runner,
                endpoint,
                config.iperf_port,
                config.iperf_seconds,
                stream_profiles=(),
                include_udp=True,
                udp_mbps=config.udp_mbps,
            )
            results.extend(item for item in udp_results if item.category == "udp")
        elif "iperf" not in config.tests:
            if config.iperf_host:
                endpoint = IperfEndpoint(
                    name="Собственный сервер",
                    city="custom",
                    host=config.iperf_host,
                    ports=(config.iperf_port,),
                    public=False,
                    supports_udp=True,
                    source="user",
                )
                udp_results = run_iperf_endpoint(
                    runner,
                    endpoint,
                    config.iperf_port,
                    config.iperf_seconds,
                    stream_profiles=(),
                    include_udp=True,
                    udp_mbps=config.udp_mbps,
                )
                results.extend(item for item in udp_results if item.category == "udp")
            else:
                results.append(
                    TestResult(
                        name="iperf3 UDP",
                        category="udp",
                        status="skipped",
                        summary="UDP разрешён только для собственного --iperf-server",
                    )
                )
        elif config.iperf_endpoints:
            results.append(
                TestResult(
                    name="iperf3 UDP",
                    category="udp",
                    status="skipped",
                    summary="UDP пропущен: собственный сервер не указан",
                )
            )
        elif not config.iperf_host and not config.iperf_endpoints:
            results.append(
                TestResult(
                    name="iperf3 UDP",
                    category="udp",
                    status="skipped",
                    summary="Не выбран iperf3 endpoint",
                )
            )

    if throughput_stage:
        progress.finish()

    score = calculate_score(results, "generic", config.expected_mbps, config.tests)
    finished_at = dt.datetime.now(dt.timezone.utc)
    progress.close()
    _ACTIVE_PROGRESS = None
    return {
        "schema_version": 2,
        "tool_version": VERSION,
        "label": config.label,
        "targets": config.targets,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "dependencies": dependency_status(
            config.tests,
            soak_iperf=bool("soak" in config.tests and config.soak_iperf_host),
        ),
        "settings": {
            "tests": sorted(config.tests),
            "ping_count": config.ping_count,
            "tcp_port": config.tcp_port,
            "soak_seconds": config.soak_seconds,
            "soak_interval_seconds": config.soak_interval_seconds,
            "soak_iperf_server": config.soak_iperf_host,
            "soak_iperf_port": config.soak_iperf_port,
            "iperf_server": config.iperf_host,
            "iperf_port": config.iperf_port,
            "iperf_endpoints": [endpoint.as_dict() for endpoint in config.iperf_endpoints],
            "iperf_catalog_mode": config.iperf_catalog_mode,
            "iperf_seconds": config.iperf_seconds,
            "iperf_streams": config.iperf_streams,
            "iperf_stream_profiles": list(IPERF_TCP_STREAM_PROFILES),
            "udp_mbps": config.udp_mbps,
            "expected_mbps": config.expected_mbps,
            "check_ip": config.check_ip,
        },
        "score": score,
        "results": [result.as_dict() for result in results],
        # Contextual hints are produced from actual results while rendering.
        # Keeping the old field makes the JSON schema backwards-compatible.
        "notes": [],
    }


def render_report(report: dict[str, Any], include_raw: bool = True) -> str:
    tests = set(report.get("settings", {}).get("tests", []))
    if tests == {"ipinfo"}:
        return render_ip_report(report, include_raw=include_raw)
    if len(tests) == 1:
        return render_focused_report(report, next(iter(tests)), include_raw=include_raw)
    return render_general_report(report, include_raw=include_raw)


def _technical_details(report: dict[str, Any]) -> list[str]:
    lines = ["", "=" * 78, "ТЕХНИЧЕСКИЕ ДЕТАЛИ", "=" * 78]
    for result in report["results"]:
        lines.extend(["", f"## {result['name']}"])
        if result.get("command"):
            lines.append(f"$ {result['command']}")
        if result.get("metrics"):
            lines.append(json.dumps(result["metrics"], ensure_ascii=False, indent=2))
        if result.get("output"):
            lines.append(result["output"].rstrip())
    return lines


def render_ip_report(report: dict[str, Any], include_raw: bool = True) -> str:
    result = next((item for item in report["results"] if item["category"] == "ipinfo"), None)
    if not result:
        return "Проверка IP не дала результата. Повторите позже.\n"
    metrics = result.get("metrics", {})
    if result.get("status") == "failed":
        lines = _title_banner("IP • ГЕОЛОКАЦИЯ • РЕПУТАЦИЯ")
        lines.extend(
            [
                "",
                f"◆ IP-АДРЕС        {metrics.get('ip', 'не определён')}",
                f"ИТОГ [НЕ ПРОВЕРЕНО]  {result.get('summary', 'не удалось получить данные')}",
                "",
                "→ Проверьте подключение к интернету и повторите тест.",
            ]
        )
        if metrics:
            lines.extend(["", _divider()])
            lines.extend(f"  {item}" for item in _ip_provider_lines(metrics))
        if include_raw:
            lines.extend(_technical_details(report))
        return "\n".join(lines).rstrip() + "\n"
    score = metrics.get("reputation_score")
    score_text = f"{score}/100" if score is not None else "не определена"
    icon = {"ok": "ХОРОШО", "warning": "ВНИМАНИЕ", "bad": "ПЛОХО", "failed": "ОШИБКА"}.get(
        result.get("status"), "ИНФО"
    )
    asn_text = ", ".join(f"AS{asn}" for asn in metrics.get("asns", [])) or "ASN не определён"
    address_type = (
        "хостинговый / дата-центр — для VPS это нормально"
        if metrics.get("hosting_or_datacenter")
        else "не подтверждён как хостинговый"
    )
    lines = _title_banner("IP • ГЕОЛОКАЦИЯ • РЕПУТАЦИЯ")
    lines.extend(
        [
            "",
            f"◆ IP-АДРЕС       {metrics.get('ip', 'не определён')}",
            f"◆ ПРОВАЙДЕР      {metrics.get('organization', 'не определён')}",
            f"◆ СЕТЬ           {asn_text}",
            f"◆ ГЕОЛОКАЦИЯ     {_country_text(metrics.get('countries', []))}",
            f"◆ РЕПУТАЦИЯ      {score_text}",
            f"  Тип адреса      {address_type}",
            "",
            f"ИТОГ [{icon}]  {metrics.get('verdict', result.get('summary', 'нет вывода'))}",
        ]
    )
    concerns = metrics.get("concerns", [])
    if concerns:
        lines.extend(["", *[f"! {item}" for item in concerns]])
    lines.extend(["", _divider()])
    lines.extend(f"  {item}" for item in _ip_provider_lines(metrics))
    if result.get("status") == "warning":
        recommendation = "Перепроверьте отмеченные сервисы через браузер и запустите проверку сайтов."
    elif result.get("status") in {"bad", "failed"}:
        recommendation = "Для основной ноды безопаснее запросить замену IP или выбрать другого провайдера."
    else:
        recommendation = None
    if recommendation:
        lines.extend(["", _divider(), "", f"→ {recommendation}"])
    if include_raw:
        lines.extend(_technical_details(report))
    return "\n".join(lines).rstrip() + "\n"


DISPLAY_STATUS = {
    "ok": "ХОРОШО",
    "warning": "ВНИМАНИЕ",
    "bad": "ПЛОХО",
    "failed": "НЕ ПРОВЕРЕНО",
    "skipped": "ПРОПУЩЕНО",
}

TEST_TITLES = {
    "ping": "PING — ЗАДЕРЖКА И ПОТЕРИ",
    "mtr": "MTR — СТАБИЛЬНОСТЬ МАРШРУТА",
    "traceroute": "TRACEROUTE — МАРШРУТ ДО ЦЕЛИ",
    "iperf": "IPERF3 TCP — СКОРОСТЬ В ОБЕ СТОРОНЫ",
    "udp": "IPERF3 UDP — ПОТЕРИ И JITTER",
    "pmtu": "PATH MTU — РАЗМЕР ПАКЕТА",
    "system": "СИСТЕМА И CPU ДЛЯ VPN",
    "tcp": "TCP/UDP-ПОРТ — ДОСТУПНОСТЬ",
    "soak": "ДЛИТЕЛЬНЫЙ СЕТЕВОЙ ТЕСТ — 5 МИНУТ",
    "access": "ДОСТУПНОСТЬ САЙТОВ",
    "dpi": "ЦЕНЗУРА И DPI — ПРИЗНАКИ ФИЛЬТРАЦИИ",
    "dnscheck": "DNS — ОБЫЧНЫЙ И ЗАЩИЩЁННЫЙ",
    "disk": "ДИСК — КОРОТКАЯ ПРОВЕРКА",
}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "cyan": "\033[96m",
    "dim": "\033[2m",
}

REPORT_WIDTH = 78
TABLE_MIN_WIDTH = 78
TABLE_MAX_WIDTH = 150


def _report_table_width() -> int:
    """Use the real console width while keeping saved reports deterministic."""
    fallback = 120
    if bool(getattr(sys.stdout, "isatty", lambda: False)()):
        fallback = shutil.get_terminal_size((120, 24)).columns
    return max(TABLE_MIN_WIDTH, min(TABLE_MAX_WIDTH, fallback))


def _clip_cell(value: Any, width: int) -> str:
    text = ("—" if value is None else str(value)).replace("\r", " ").replace("\n", " ")
    if width <= 1:
        return text[:width]
    return text if len(text) <= width else text[: width - 1] + "…"


def _plain_table(headers: list[str], rows: list[list[Any]], widths: list[int]) -> list[str]:
    """Render a compact terminal table without external dependencies."""
    if len(headers) != len(widths) or any(len(row) != len(headers) for row in rows):
        raise ValueError("Некорректные размеры таблицы")

    def render_row(values: list[Any]) -> str:
        return "  ".join(
            _clip_cell(value, width).ljust(width)
            for value, width in zip(values, widths, strict=True)
        ).rstrip()

    lines = [render_row(headers), render_row(["─" * width for width in widths])]
    lines.extend(render_row(row) for row in rows)
    return lines


def _title_banner(title: str) -> list[str]:
    inner = REPORT_WIDTH - 2
    visible = title[: inner - 3]
    return [
        "╭" + "─" * inner + "╮",
        "│ " + visible.ljust(inner - 2) + " │",
        "╰" + "─" * inner + "╯",
    ]


def _divider() -> str:
    return "─" * REPORT_WIDTH


def clear_console(*, enabled: bool = True) -> None:
    """Clear only an interactive terminal; redirected logs remain untouched."""
    if not enabled or not bool(getattr(sys.stdout, "isatty", lambda: False)()):
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["cmd", "/c", "cls"],
                stdout=sys.stdout,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return
        except OSError:
            pass
    # Clear the visible page first, then its saved scrollback.  This order also
    # handles PuTTY's default "push erased text into scrollback" behaviour.
    # PuTTY may deliberately ignore CSI 3 J if remote clearing is disabled.
    sys.stdout.write("\033[2J\033[3J\033[H")
    sys.stdout.flush()


def _terminal_supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not bool(getattr(sys.stdout, "isatty", lambda: False)()):
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        pass
    return bool(
        os.environ.get("WT_SESSION")
        or os.environ.get("ANSICON")
        or os.environ.get("TERM")
        or os.environ.get("ConEmuANSI") == "ON"
    )


def colorize_report(text: str, *, enabled: bool = True) -> str:
    """Color semantic console lines without contaminating TXT/JSON reports."""
    use_color = enabled and _terminal_supports_color()
    colored: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        color = None
        if line.startswith("TABLE|"):
            cells = line.split("|")[1:]
            if not use_color:
                colored.append("".join(cells))
                continue
            first_cell = cells[0].strip() if cells else ""
            is_header = first_cell in {
                "СЕРВИС",
                "RESOLVER",
                "#",
                "ХОП",
                "ОПЕРАЦИЯ",
                "ЦЕЛЬ",
                "ТОЧКА",
                "ПОКАЗАТЕЛЬ",
                "ТЕСТ",
                "ПРОГРАММА",
            }
            is_separator = bool(first_cell) and not first_cell.strip("─")
            rendered: list[str] = []
            for cell in cells:
                cell_color = None
                value = cell.strip()
                if is_header:
                    cell = f"{ANSI['bold']}{ANSI['cyan']}{cell}{ANSI['reset']}"
                elif is_separator:
                    cell = f"{ANSI['dim']}{cell}{ANSI['reset']}"
                elif any(
                    token in value
                    for token in ("Доступен", "Перенаправлен", "Работает", "Ответ", "ХОРОШО", "ИЗМЕРЕНО")
                ):
                    cell_color = "green" if "Перенаправлен" not in value else "cyan"
                elif any(
                    token in value
                    for token in (
                        "Предупреждение",
                        "Не проверено",
                        "Не разобрано",
                        "Частичный",
                        "HTTP 403",
                        "HTTP 451",
                        "ВНИМАНИЕ",
                        "ПРОПУЩЕНО",
                        "ТЕСТ ПРОПУЩЕН",
                        "ЧАСТЬ ДАННЫХ ПРОПУЩЕНА",
                        "НЕ ПРОВЕРЕНО",
                        "НЕ ОПРЕДЕЛЕНО",
                    )
                ):
                    cell_color = "yellow"
                elif "СПРАВОЧНО" in value:
                    cell_color = "cyan"
                elif value == "*" or any(
                    token in value
                    for token in ("Нет соединения", "Нет ответа", "Недоступен", "Ошибка", "ПЛОХО")
                ):
                    cell_color = "red"
                if cell_color and not (is_header or is_separator):
                    cell = f"{ANSI[cell_color]}{cell}{ANSI['reset']}"
                rendered.append(cell)
            colored.append("".join(rendered))
            continue
        if not use_color:
            colored.append(line)
            continue
        if any(token in line for token in ("[ХОРОШО]", "[OK]")) or stripped.startswith(("✓", "+", "[OK]")):
            color = "green"
        elif any(token in line for token in ("[ВНИМАНИЕ]", "[ПРОПУЩЕНО]", "[НЕ ПРОВЕРЕНО]")) or stripped.startswith(("!", "[WARN]", "[SKIP]")):
            color = "yellow"
        elif any(token in line for token in ("[ПЛОХО]", "[ОШИБКА]")) or stripped.startswith(("✗", "[FAIL]", "[BAD]")):
            color = "red"
        elif stripped.startswith(("◆", "ИТОГ", "ОБЩАЯ ОЦЕНКА", "ОБЩИЙ ИТОГ")):
            color = "cyan"
        elif stripped.startswith(("╭", "│", "╰")):
            line = f"{ANSI['bold']}{ANSI['cyan']}{line}{ANSI['reset']}"
            colored.append(line)
            continue
        elif stripped.startswith(("─", "·", "→")):
            line = f"{ANSI['dim']}{line}{ANSI['reset']}"
            colored.append(line)
            continue
        if color:
            line = f"{ANSI[color]}{line}{ANSI['reset']}"
        colored.append(line)
    return "\n".join(colored) + ("\n" if text.endswith("\n") else "")


def _semantic_table(headers: list[str], rows: list[list[Any]], widths: list[int]) -> list[str]:
    """Prefix table cells so the console colorizer can color statuses per cell."""
    if len(headers) != len(widths) or any(len(row) != len(headers) for row in rows):
        raise ValueError("Некорректные размеры таблицы")

    def encoded(values: list[Any]) -> str:
        cells = []
        for index, (value, width) in enumerate(zip(values, widths, strict=True)):
            suffix = "  " if index < len(widths) - 1 else ""
            cells.append(_clip_cell(value, width).ljust(width) + suffix)
        return "TABLE|" + "|".join(cells)

    lines = [encoded(headers), encoded(["─" * width for width in widths])]
    lines.extend(encoded(row) for row in rows)
    return lines


def _wrapped_semantic_table(
    headers: list[str], rows: list[list[Any]], widths: list[int]
) -> list[str]:
    """Wrap long descriptions and visibly separate logical table rows."""
    if len(headers) != len(widths) or any(len(row) != len(headers) for row in rows):
        raise ValueError("Некорректные размеры таблицы")
    expanded: list[list[str]] = []
    for row_index, row in enumerate(rows):
        wrapped_cells: list[list[str]] = []
        for value, width in zip(row, widths, strict=True):
            wrapped_cells.append(
                textwrap.wrap(
                    str(value or "—"),
                    width=width,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                or ["—"]
            )
        height = max(len(cell) for cell in wrapped_cells)
        for line_index in range(height):
            expanded.append(
                [
                    cell[line_index] if line_index < len(cell) else ""
                    for cell in wrapped_cells
                ]
            )
        if row_index < len(rows) - 1:
            expanded.append(["─" * width for width in widths])
    return _semantic_table(headers, expanded, widths)


def _display_number(value: Any, suffix: str = "", digits: int = 1) -> str:
    if value is None:
        return "не определено"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return f"{value}{suffix}"
    text = f"{number:.{digits}f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text}{suffix}"


def _endpoint_name(result: dict[str, Any]) -> str:
    endpoint = result.get("metrics", {}).get("endpoint")
    if isinstance(endpoint, dict):
        city = endpoint.get("city")
        name = endpoint.get("name")
        if city == "custom":
            return str(name or endpoint.get("host") or "свой сервер")
        return ", ".join(str(value) for value in (city, name) if value)
    return result.get("name", "результат")


def _friendly_network_error(error: Any) -> str:
    text = str(error or "").lower()
    if not text:
        return "причина не определена"
    if "timed out" in text or "timeout" in text or "тайм" in text:
        return "истекло время ожидания ответа"
    if "name or service" in text or "getaddrinfo" in text or "nodename" in text:
        return "не удалось определить IP сайта через DNS"
    if "certificate" in text or "ssl" in text:
        return "ошибка защищённого TLS-соединения"
    if "10013" in text or "permission" in text or "access denied" in text:
        return "соединение запрещено локальной системой или firewall"
    if "reset" in text or "remote end closed" in text:
        return "удалённый сервер разорвал соединение"
    if "429" in text:
        return "сервис временно ограничил частоту запросов"
    return "соединение не установлено; техническая причина доступна при ручном сохранении TXT"


def _ip_provider_lines(metrics: dict[str, Any]) -> list[str]:
    providers = metrics.get("providers", {})
    titles = {
        "ipapi.is": "ipapi.is",
        "ipwho.is": "ipwho.is",
        "ipapi.co": "ipapi.co",
    }
    signal_labels = {
        "is_vpn": "VPN",
        "is_proxy": "proxy",
        "is_tor": "Tor",
        "is_abuser": "abuse",
        "is_bogon": "bogon",
    }
    lines: list[str] = []
    for provider in titles:
        data = providers.get(provider, {})
        if not data or data.get("error"):
            lines.append(
                f"! {titles[provider]}: база не ответила — {_friendly_network_error(data.get('error'))}."
            )
            continue
        country = str(data.get("country") or "страна не определена").upper()
        country_text = COUNTRY_NAMES_RU.get(country, country)
        location = ", ".join(
            str(value) for value in (data.get("region"), data.get("city")) if value
        )
        asn = str(data.get("asn") or "").upper().removeprefix("AS")
        organization = data.get("organization")
        identity = country_text
        if location:
            identity += f", {location}"
        if asn:
            identity += f"; AS{asn}"
        if organization:
            identity += f" — {organization}"
        available_signal_keys = [key for key in signal_labels if isinstance(data.get(key), bool)]
        flagged = [signal_labels[key] for key in available_signal_keys if data.get(key) is True]
        if flagged:
            conclusion = f"предупреждение: флаги {', '.join(flagged)}"
            marker = "!"
        elif available_signal_keys:
            checked = "/".join(signal_labels[key] for key in available_signal_keys)
            conclusion = f"флаги {checked} не обнаружены"
            marker = "✓"
        else:
            conclusion = "эта база сообщает гео/ASN без репутационных флагов"
            marker = "✓"
        lines.append(f"{marker} {titles[provider]}: {identity}; {conclusion}.")

    rdap = metrics.get("rdap", {})
    if rdap.get("error"):
        lines.append(f"! RIPE RDAP: владелец диапазона не получен — {_friendly_network_error(rdap['error'])}.")
    elif rdap:
        owner = rdap.get("name") or rdap.get("handle") or "владелец не назван"
        address_range = ""
        if rdap.get("start_address") and rdap.get("end_address"):
            address_range = f"; диапазон {rdap['start_address']}–{rdap['end_address']}"
        lines.append(f"✓ RIPE RDAP: зарегистрированный владелец/сеть — {owner}{address_range}.")

    spamhaus = metrics.get("spamhaus_drop", {})
    if spamhaus.get("listed") is True:
        lines.append("✗ Spamhaus DROP: подсеть найдена в списке опасных сетей — серьёзный риск.")
    elif spamhaus.get("checked") is True:
        lines.append("✓ Spamhaus DROP: подсеть не найдена в списке опасных сетей.")
    else:
        lines.append("! Spamhaus DROP: сервис не ответил, эту часть репутации оценить не удалось.")
    return lines


def _access_check_lines(checks: list[dict[str, Any]]) -> list[str]:
    rows: list[list[Any]] = []
    for item in checks:
        http = item.get("http", {})
        https = item.get("https", item)
        rows.append(
            [
                item.get("domain") or item.get("name", "Сервис"),
                item.get("ip") or "—",
                _http_table_status(http),
                _http_table_status(https),
            ]
        )
    total_width = _report_table_width()
    service_width = min(27, max(18, max((len(str(row[0])) for row in rows), default=18)))
    ip_width = 15
    https_width = 21
    http_width = max(22, total_width - service_width - ip_width - https_width - 6)
    return _semantic_table(
        ["СЕРВИС", "IP", "HTTP", "HTTPS"],
        rows,
        [service_width, ip_width, http_width, https_width],
    )


def _http_table_status(probe: dict[str, Any]) -> str:
    if not probe.get("reachable"):
        return "Нет соединения"
    code = probe.get("status_code")
    redirect = probe.get("redirect_url")
    if code is not None and 300 <= int(code) <= 399:
        suffix = f" → {redirect}" if redirect else ""
        return f"Перенаправлен ({code}){suffix}"
    if code in {403, 451}:
        return f"Предупреждение ({code})"
    if code is not None and 200 <= int(code) <= 299:
        return f"Доступен ({code})"
    if code in {401, 404, 429}:
        return f"Доступен ({code})"
    return f"Ошибка HTTP {code}" if code is not None else "Нет соединения"


def _dns_check_lines(metrics: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    system = metrics.get("system_dns", {})
    if system.get("available"):
        lines.append(
            f"✓ Системный DNS: отвечает за {_display_number(system.get('elapsed_ms'), ' мс', 0)}."
        )
    else:
        lines.append(f"✗ Системный DNS: {_friendly_network_error(system.get('error'))}.")
    rows: list[list[Any]] = []
    for resolver in metrics.get("resolvers", []):
        transports = resolver.get("transports", {})
        rows.append(
            [
                resolver.get("name"),
                resolver.get("address"),
                _dns_table_status(transports.get("udp", {})),
                _dns_table_status(transports.get("tcp", {})),
                _dns_table_status(transports.get("doh", {})),
                _dns_table_status(transports.get("dot", {})),
            ]
        )
    lines.extend(
        _semantic_table(
            ["RESOLVER", "IP", "UDP/53", "TCP/53", "DoH/443", "DoT/853"],
            rows,
            [12, 15, 17, 17, 17, 17],
        )
    )
    return lines


def _dns_table_status(probe: dict[str, Any]) -> str:
    if probe.get("supported") is False:
        return "Не проверено"
    if probe.get("available"):
        elapsed = probe.get("elapsed_ms")
        return f"Работает ({float(elapsed):.0f} мс)" if elapsed is not None else "Работает"
    return "Недоступен"


def _dpi_check_lines(checks: list[dict[str, Any]]) -> list[str]:
    rows: list[list[Any]] = []
    for item in checks:
        http = item.get("http", {})
        https = item.get("https", {})
        rows.append(
            [
                item.get("domain") or item.get("name"),
                https.get("ip") or http.get("ip") or "—",
                _http_table_status(http),
                _http_table_status(https),
            ]
        )
    total_width = _report_table_width()
    service_width = min(29, max(18, max((len(str(row[0])) for row in rows), default=18)))
    ip_width = 15
    https_width = 21
    http_width = max(22, total_width - service_width - ip_width - https_width - 6)
    return _semantic_table(
        ["СЕРВИС", "IP", "HTTP", "HTTPS"],
        rows,
        [service_width, ip_width, http_width, https_width],
    )


def _mtr_hop_rows(output: str) -> list[list[Any]]:
    rows: list[list[Any]] = []
    pattern = re.compile(
        r"^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+"
        r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        hop, host, loss, _sent, _last, avg, best, worst, jitter = match.groups()
        rows.append(
            [
                hop,
                host,
                f"{float(loss):g}%",
                f"{float(avg):g} мс",
                f"{float(best):g} мс",
                f"{float(worst):g} мс",
                f"{float(jitter):g} мс",
            ]
        )
    return rows


_TRACEROUTE_PROBE_RE = re.compile(
    r"\*|<\s*\d+(?:[.,]\d+)?\s*(?:ms|мс)|\d+(?:[.,]\d+)?\s*(?:ms|мс)",
    re.IGNORECASE,
)


def _traceroute_probe_text(value: str) -> str:
    value = value.strip()
    if value == "*":
        return "*"
    compact = re.sub(r"\s+", "", value, flags=re.UNICODE).lower().replace("ms", "").replace("мс", "")
    return f"{compact.replace(',', '.')} мс"


def _traceroute_hop_rows(hop_lines: list[str]) -> list[list[Any]]:
    """Parse Windows tracert and Linux traceroute hops without dropping odd lines."""
    rows: list[list[Any]] = []
    timeout_tokens = ("timed out", "timeout", "превышен интервал", "истек", "нет ответа")
    for line in hop_lines:
        hop_match = re.match(r"^\s*(\d+)\s+(.*)$", line.rstrip())
        if not hop_match:
            continue
        hop, payload = hop_match.groups()
        matches = list(_TRACEROUTE_PROBE_RE.finditer(payload))
        if not matches:
            rows.append([hop, payload.strip() or "—", "—", "—", "—", "Не разобрано"])
            continue

        leading_probes = not payload[: matches[0].start()].strip()
        if leading_probes:
            node = payload[matches[-1].end() :].strip()
            annotation = ""
        else:
            node = payload[: matches[0].start()].strip()
            annotation = payload[matches[-1].end() :].strip()

        probes = [_traceroute_probe_text(match.group()) for match in matches[:3]]
        probes.extend(["—"] * (3 - len(probes)))
        timeout_text = node.casefold()
        if any(token in timeout_text for token in timeout_tokens):
            node = "—"
        if all(probe == "*" for probe in probes if probe != "—"):
            status = "Нет ответа"
        elif "*" in probes:
            status = "Частичный ответ"
        elif annotation.startswith("!"):
            status = f"Ошибка {annotation}"
        else:
            status = "Ответ"
        rows.append([hop, node or "—", *probes, status])
    return rows


def _traceroute_table(hop_rows: list[list[Any]]) -> list[str]:
    total_width = _report_table_width()
    hop_width = 4
    rtt_width = 10
    status_width = 16 if total_width >= 100 else 14
    separators_width = 10
    node_width = min(
        45,
        max(18, total_width - hop_width - (rtt_width * 3) - status_width - separators_width),
    )
    return _semantic_table(
        ["ХОП", "УЗЕЛ / IP", "RTT 1", "RTT 2", "RTT 3", "СТАТУС"],
        hop_rows,
        [hop_width, node_width, rtt_width, rtt_width, rtt_width, status_width],
    )


def _result_target(result: dict[str, Any]) -> str:
    """Extract the human-facing target without depending on a technical command."""
    name = str(result.get("name") or "цель")
    if "→" in name:
        return name.rsplit("→", 1)[-1].strip()
    return name


def _result_status(result: dict[str, Any]) -> str:
    return DISPLAY_STATUS.get(str(result.get("status", "failed")), "НЕ ПРОВЕРЕНО")


def _crypto_throughput_mbps(metrics: dict[str, Any]) -> float | None:
    value = metrics.get("throughput_mbps")
    if isinstance(value, (int, float)):
        return float(value)
    legacy = metrics.get("estimated_gbps")
    if isinstance(legacy, (int, float)):
        return float(legacy) * 1_000
    return None


def _crypto_display_status(result: dict[str, Any], speed_mbps: float | None) -> str:
    if result.get("status") in {"failed", "skipped"}:
        return _result_status(result)
    status, _ = _crypto_benchmark_assessment(speed_mbps)
    return DISPLAY_STATUS.get(status, "ОШИБКА")


def _throughput_status(speed: float, expected_mbps: int | None) -> str:
    if not expected_mbps:
        if speed >= 300:
            return "ХОРОШО"
        if speed >= 100:
            return "ВНИМАНИЕ"
        return "ПЛОХО"
    if speed >= expected_mbps:
        return "ХОРОШО"
    if speed >= expected_mbps * 0.7:
        return "ВНИМАНИЕ"
    return "ПЛОХО"


def _iperf_retransmit_text(metrics: dict[str, Any]) -> str:
    retransmits = metrics.get("retransmits")
    if retransmits is None:
        return "—"
    normalized = metrics.get("retransmits_per_gib")
    if normalized is None:
        return str(retransmits)
    return f"{retransmits} ({_display_number(normalized, '/ГиБ')})"


def _compact_count(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    number = float(value)
    absolute = abs(number)
    if absolute >= 1_000_000:
        return f"{number / 1_000_000:.1f}m"
    if absolute >= 1_000:
        return f"{number / 1_000:.1f}k"
    return f"{number:g}"


def _group_iperf_directions(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for result in results:
        metrics = result.get("metrics", {})
        endpoint = metrics.get("endpoint")
        if isinstance(endpoint, dict):
            key = (
                endpoint.get("host"),
                metrics.get("selected_port"),
                endpoint.get("city"),
                endpoint.get("name"),
                metrics.get("streams"),
            )
        else:
            key = (
                _endpoint_name(result),
                metrics.get("selected_port"),
                metrics.get("streams"),
            )
        group = groups.setdefault(
            key,
            {"name": _endpoint_name(result), "upload": None, "download": None},
        )
        direction = metrics.get("direction")
        if direction in {"upload", "download"}:
            group[direction] = result
    return list(groups.values())


def _iperf_pair_streams(group: dict[str, Any]) -> str:
    values = []
    for direction in ("upload", "download"):
        result = group.get(direction)
        value = result.get("metrics", {}).get("streams") if result else None
        values.append(value)
    if values[0] is not None and values[0] == values[1]:
        return str(values[0])
    return f"U {values[0] if values[0] is not None else '—'} · D {values[1] if values[1] is not None else '—'}"


def _iperf_pair_retransmits(group: dict[str, Any]) -> str:
    values: list[str] = []
    for direction in ("upload", "download"):
        result = group.get(direction)
        metrics = result.get("metrics", {}) if result else {}
        normalized = metrics.get("retransmits_per_gib")
        if isinstance(normalized, (int, float)):
            values.append(_compact_count(normalized))
        elif metrics.get("retransmits") == 0:
            values.append("0")
        else:
            values.append("—")
    return f"U {values[0]} · D {values[1]}"


def _iperf_pair_cpu(group: dict[str, Any]) -> str:
    values: list[str] = []
    for direction in ("upload", "download"):
        result = group.get(direction)
        cpu = result.get("metrics", {}).get("local_cpu_percent") if result else None
        values.append(_display_number(cpu, "%", 1))
    return f"U {values[0]} · D {values[1]}"


def _worst_iperf_status(statuses: list[str]) -> str:
    rank = {"ХОРОШО": 0, "ИЗМЕРЕНО": 0, "НЕ ПРОВЕРЕНО": 1, "ВНИМАНИЕ": 1, "ПЛОХО": 2}
    return max(statuses or ["НЕ ПРОВЕРЕНО"], key=lambda item: rank.get(item, 1))


def _iperf_endpoint_status(
    group: dict[str, Any],
    expected_mbps: int | None,
) -> str:
    statuses: list[str] = []
    is_public = False
    for direction in ("upload", "download"):
        result = group.get(direction)
        metrics = result.get("metrics", {}) if result else {}
        endpoint = metrics.get("endpoint")
        if isinstance(endpoint, dict) and endpoint.get("public"):
            is_public = True
        speed = metrics.get("mbps")
        statuses.append(
            _throughput_status(float(speed), expected_mbps)
            if isinstance(speed, (int, float))
            else "ВНИМАНИЕ"
        )
        normalized = metrics.get("retransmits_per_gib")
        if isinstance(normalized, (int, float)):
            retransmission_status = _iperf_retransmission_status(float(normalized))
            if is_public and retransmission_status == "ПЛОХО":
                retransmission_status = "ВНИМАНИЕ"
            statuses.append(retransmission_status)
    return _worst_iperf_status(statuses)


def _tabular_group(category: str) -> str | None:
    if category in {"ping", "tcp", "iperf", "udp", "disk"}:
        return category
    if category == "udp_port":
        return "tcp"
    if category in {"soak", "soak_iperf"}:
        return "soak"
    if category in {"system", "crypto"}:
        return "system"
    return None


def _tabular_result_section(
    group: str,
    results: list[dict[str, Any]],
    expected_mbps: int | None,
) -> list[str]:
    """Render comparable measurements once, with one header for all targets."""
    total_width = _report_table_width()

    if group == "disk":
        result = results[0]
        metrics = result.get("metrics", {})
        size = metrics.get("size_mib")
        size_text = f"{size} МиБ" if size is not None else "—"
        if "write_fsync_mib_s" not in metrics:
            return [
                "◆ КОРОТКИЙ ТЕСТ ДИСКА",
                *_semantic_table(
                    ["ОПЕРАЦИЯ", "ОБЪЁМ", "СКОРОСТЬ", "СТАТУС"],
                    [["Disk I/O", size_text, "—", _result_status(result)]],
                    [25, 11, 17, 17],
                ),
                "",
                f"! {result.get('summary', 'Измерение диска не выполнено.')}",
            ]
        return [
            "◆ КОРОТКИЙ ТЕСТ ДИСКА",
            *_semantic_table(
                ["ОПЕРАЦИЯ", "ОБЪЁМ", "СКОРОСТЬ", "СТАТУС"],
                [
                    [
                        "Запись + fsync",
                        size_text,
                        _display_number(metrics.get("write_fsync_mib_s"), " МиБ/с"),
                        _result_status(result),
                    ],
                    [
                        "Чтение (возможен кэш)",
                        size_text,
                        _display_number(metrics.get("read_mib_s"), " МиБ/с"),
                        "СПРАВОЧНО",
                    ],
                ],
                [25, 11, 17, 17],
            ),
        ]

    if group == "ping":
        target_width = min(45, max(18, total_width - 67))
        rows: list[list[Any]] = []
        no_reply: list[str] = []
        for result in results:
            metrics = result.get("metrics", {})
            loss = metrics.get("loss_percent")
            if loss is not None and float(loss) >= 100:
                no_reply.append(_result_target(result))
            rows.append(
                [
                    _result_target(result),
                    metrics.get("transmitted", "—"),
                    _display_number(metrics.get("avg_ms"), " мс"),
                    _display_number(loss, "%"),
                    _display_number(metrics.get("jitter_ms"), " мс"),
                    _result_status(result),
                ]
            )
        lines = [
            "◆ PING ПО КАЖДОЙ ЦЕЛИ",
            *_semantic_table(
                ["ЦЕЛЬ", "ЗАПРОСЫ", "СР. RTT", "ПОТЕРИ", "РАЗБРОС", "СТАТУС"],
                rows,
                [target_width, 9, 11, 10, 11, 16],
            ),
        ]
        if no_reply:
            lines.extend(
                [
                    "",
                    _divider(),
                    "",
                    f"! Нет ответов от: {', '.join(no_reply)}.",
                    "· Сервер не обязательно выключен: firewall мог запретить ICMP.",
                    "→ Проверьте рабочий TCP-порт или запустите MTR.",
                ]
            )
        return lines

    if group == "tcp":
        rows = []
        unavailable: list[str] = []
        silent_udp: list[str] = []
        refused_udp: list[str] = []
        for result in results:
            metrics = result.get("metrics", {})
            protocol = str(metrics.get("protocol") or "TCP")
            attempts = int(metrics.get("attempts", 0))
            if protocol == "UDP":
                responses = int(metrics.get("responses", 0))
                refusals = int(metrics.get("refusals", 0))
                if responses:
                    outcome = f"ответ {responses} из {attempts}"
                elif refusals:
                    outcome = "получен отказ"
                    refused_udp.append(_result_target(result))
                else:
                    outcome = "нет ответа"
                    silent_udp.append(_result_target(result))
                latency = _display_number(metrics.get("response_avg_ms"), " мс")
            else:
                success = int(metrics.get("successful_connections", 0))
                if attempts and success == 0:
                    unavailable.append(_result_target(result))
                outcome = f"{success} из {attempts}" if attempts else "—"
                latency = _display_number(metrics.get("tcp_avg_ms"), " мс")
            rows.append(
                [
                    _result_target(result),
                    protocol,
                    metrics.get("port", "—"),
                    outcome,
                    latency,
                    _result_status(result),
                ]
            )
        if total_width < 90:
            compact_rows = [[f"{row[0]} • {row[1]}", *row[2:]] for row in rows]
            table = _semantic_table(
                ["ЦЕЛЬ", "ПОРТ", "РЕЗУЛЬТАТ", "СР. RTT", "СТАТУС"],
                compact_rows,
                [24, 7, 15, 10, 14],
            )
        else:
            target_width = min(38, max(17, total_width - 67))
            table = _semantic_table(
                ["ЦЕЛЬ", "ПРОТОКОЛ", "ПОРТ", "РЕЗУЛЬТАТ", "СР. RTT", "СТАТУС"],
                rows,
                [target_width, 9, 7, 16, 11, 14],
            )
        lines = ["◆ ДОСТУПНОСТЬ TCP И UDP", *table]
        if unavailable or refused_udp or silent_udp:
            hints = []
            if unavailable:
                hints.extend(
                    [
                        f"! Ни одного TCP-подключения: {', '.join(unavailable)}.",
                        "→ Проверьте номер порта, firewall и запущен ли TCP-сервис на цели.",
                    ]
                )
            if refused_udp:
                hints.append(
                    f"! UDP получил явный отказ от: {', '.join(refused_udp)} — порт закрыт или недоступен."
                )
            if silent_udp:
                hints.append(
                    f"· UDP не ответил: {', '.join(silent_udp)}. Это означает «открыт или фильтруется»; многие UDP-сервисы игнорируют незнакомый пакет."
                )
            lines.extend(
                [
                    "",
                    _divider(),
                    "",
                    *hints,
                ]
            )
        return lines

    if group == "iperf":
        measured = [item for item in results if "mbps" in item.get("metrics", {})]
        if not measured:
            missing_tool = next(
                (
                    item
                    for item in results
                    if item.get("status") == "skipped"
                    and "не установлена" in item.get("summary", "")
                ),
                None,
            )
            if missing_tool:
                return _iperf_missing_lines(missing_tool)
        grouped = _group_iperf_directions(results)
        rows = []
        for endpoint in grouped:
            upload = endpoint.get("upload")
            download = endpoint.get("download")
            upload_metrics = upload.get("metrics", {}) if upload else {}
            download_metrics = download.get("metrics", {}) if download else {}
            rows.append(
                [
                    endpoint["name"],
                    _iperf_pair_streams(endpoint),
                    _display_number(upload_metrics.get("mbps"), " Мбит/с"),
                    _display_number(download_metrics.get("mbps"), " Мбит/с"),
                    _iperf_pair_retransmits(endpoint),
                    _iperf_pair_cpu(endpoint),
                    _iperf_endpoint_status(endpoint, expected_mbps),
                ]
            )
        def render_profile_table(profile_rows: list[list[Any]]) -> list[str]:
            if total_width < 100:
                point_width = max(17, total_width - 56)
                compact_rows = [
                    [row[0], row[1], row[2], row[3], row[4], row[6]]
                    for row in profile_rows
                ]
                return _semantic_table(
                    ["ТОЧКА", "ПОТОКИ", "UPLOAD", "DOWNLOAD", "RETR/ГиБ U/D", "СТАТУС"],
                    compact_rows,
                    [point_width, 5, 9, 9, 13, 10],
                )
            if total_width < 120:
                point_width = max(17, total_width - 83)
                widths = [point_width, 7, 12, 12, 17, 11, 12]
            else:
                point_width = min(43, max(24, total_width - 90))
                widths = [point_width, 7, 13, 13, 18, 15, 12]
            return _semantic_table(
                [
                    "ТОЧКА",
                    "ПОТОКИ",
                    "UPLOAD",
                    "DOWNLOAD",
                    "TCP-ПОВТОРЫ/ГиБ",
                    "CPU U/D",
                    "СТАТУС",
                ],
                profile_rows,
                widths,
            )

        profile_rows: dict[str, list[list[Any]]] = {}
        for row in rows:
            profile_rows.setdefault(str(row[1]), []).append(row)
        profile_order = sorted(
            profile_rows,
            key=lambda value: int(value) if value.isdigit() else 999,
        )
        lines = ["◆ IPERF3 TCP ПО КАЖДОЙ ТОЧКЕ"]
        for index, profile in enumerate(profile_order):
            if index:
                lines.append("")
            suffix = "ПОТОК" if profile == "1" else "ПОТОКА"
            lines.extend(
                [
                    f"◇ ПРОФИЛЬ: {profile} TCP-{suffix}",
                    *render_profile_table(profile_rows[profile]),
                ]
            )
        skipped = list(
            dict.fromkeys(
                str(item.get("summary"))
                for item in results
                if "mbps" not in item.get("metrics", {}) and item.get("summary")
            )
        )
        details = [f"! {item}" for item in skipped]
        one_stream_speed = _representative_iperf_speed(
            [item.get("metrics", {}) for item in measured if item.get("metrics", {}).get("streams") == 1]
        )
        four_stream_speed = _representative_iperf_speed(
            [item.get("metrics", {}) for item in measured if item.get("metrics", {}).get("streams") == 4]
        )
        if one_stream_speed is not None and four_stream_speed is not None:
            details.append(
                f"· Один поток: {one_stream_speed:g} Мбит/с; четыре потока: {four_stream_speed:g} Мбит/с. Для ёмкости и общего балла используется профиль 4 потока."
            )
            if one_stream_speed < four_stream_speed * 0.55:
                details.append(
                    "! Один TCP-поток заметно медленнее четырёх: отдельное VPN-соединение может упираться в RTT, TCP-окно, маршрут или одно ядро."
                )
        normalized_values = [
            float(item["metrics"]["retransmits_per_gib"])
            for item in results
            if isinstance(item.get("metrics", {}).get("retransmits_per_gib"), (int, float))
        ]
        if normalized_values:
            details.append(
                "· TCP-повторы показаны на 1 ГиБ: U — upload, D — download. Это повторно отправленные TCP-сегменты, а не точный процент потерь."
            )
            details.append(
                "· Эвристика: до 500/ГиБ — хорошо; 501–5000 — внимание; больше 5000 — плохо для своей контрольной точки."
            )
            public_results = [
                item
                for item in results
                if isinstance(item.get("metrics", {}).get("endpoint"), dict)
                and item["metrics"]["endpoint"].get("public")
            ]
            if public_results:
                details.append(
                    "· На публичных серверах повторы имеют пониженный вес: причиной может быть загрузка самой точки. Высокое значение даёт предупреждение, а не автоматический красный итог."
                )
            if max(normalized_values) > 5_000:
                details.append(
                    "! Большое число повторов означает потери/перегрузку на пути или самой тестовой точки, даже если TCP сохранил высокую скорость повторной отправкой данных."
                )
        if details:
            lines.extend(["", _divider(), "", *details])
        return lines

    if group == "soak":
        rows = []
        hints: list[str] = []
        stability = next(
            (item for item in results if item.get("category") == "soak"),
            None,
        )
        throughput = next(
            (item for item in results if item.get("category") == "soak_iperf"),
            None,
        )
        if stability:
            metrics = stability.get("metrics", {})
            rows.extend(
                [
                    [
                        "Продолжительность",
                        _format_duration(metrics.get("requested_duration_seconds")),
                        "ИЗМЕРЕНО",
                    ],
                    [
                        "Интервалы наблюдения",
                        metrics.get("sample_windows", 0),
                        "ИЗМЕРЕНО",
                    ],
                    [
                        "Потери ping",
                        _display_number(metrics.get("loss_percent"), "%"),
                        _result_status(stability),
                    ],
                    [
                        "RTT средняя / p95 / пик",
                        " / ".join(
                            _display_number(metrics.get(key), " мс")
                            for key in ("avg_ms", "p95_ms", "max_window_avg_ms")
                        ),
                        _result_status(stability),
                    ],
                    [
                        "Всплески RTT",
                        metrics.get("rtt_spike_windows", 0),
                        _result_status(stability),
                    ],
                    [
                        "TCP-подключения",
                        f"{metrics.get('tcp_successes', 0)} из {metrics.get('tcp_attempts', 0)} ({_display_number(metrics.get('tcp_success_percent'), '%')})",
                        _result_status(stability),
                    ],
                    [
                        "Полные обрывы интервалов",
                        metrics.get("outage_windows", 0),
                        _result_status(stability),
                    ],
                ]
            )
        if throughput:
            metrics = throughput.get("metrics", {})
            if "mbps" in metrics:
                rows.extend(
                    [
                        ["Параллельные TCP-потоки", metrics.get("streams", "—"), "ИЗМЕРЕНО"],
                        [
                            "Средняя скорость под нагрузкой",
                            _display_number(metrics.get("mbps"), " Мбит/с"),
                            _result_status(throughput),
                        ],
                        [
                            "Мин. / макс. интервал",
                            f"{_display_number(metrics.get('interval_min_mbps'), ' Мбит/с')} / {_display_number(metrics.get('interval_max_mbps'), ' Мбит/с')}",
                            _result_status(throughput),
                        ],
                        [
                            "Разброс скорости",
                            _display_number(metrics.get("interval_cv_percent"), "%"),
                            _result_status(throughput),
                        ],
                        [
                            "Снижение скорости к концу",
                            _display_number(metrics.get("sustained_drop_percent"), "%"),
                            _result_status(throughput),
                        ],
                        [
                            "TCP-повторы",
                            _iperf_retransmit_text(metrics),
                            "ИЗМЕРЕНО",
                        ],
                        [
                            "CPU iperf3",
                            _display_number(metrics.get("local_cpu_percent"), "%"),
                            "ИЗМЕРЕНО",
                        ],
                    ]
                )
                if float(metrics.get("sustained_drop_percent", 0)) >= 20:
                    hints.append(
                        "! Скорость заметно снизилась к концу теста: возможен burst-лимит, перегрузка или нагрев/ограничение CPU."
                    )
            else:
                rows.append(
                    ["Burst-лимит скорости", throughput.get("summary"), _result_status(throughput)]
                )
                hints.append(
                    "· Для проверки burst-лимита нужен собственный iperf3-сервер; публичную точку нельзя занимать нагрузкой на пять минут."
                )
        value_width = min(70, max(29, total_width - 53))
        lines = [
            "◆ СТАБИЛЬНОСТЬ ВО ВРЕМЕНИ",
            *_wrapped_semantic_table(
                ["ПОКАЗАТЕЛЬ", "ЗНАЧЕНИЕ", "СТАТУС"],
                rows,
                [31, value_width, 18],
            ),
        ]
        if hints:
            lines.extend(["", _divider(), "", *hints])
        return lines

    if group == "udp":
        rows = []
        for result in results:
            metrics = result.get("metrics", {})
            direction = metrics.get("direction")
            rows.append(
                [
                    _endpoint_name(result),
                    "К СЕРВЕРУ" if direction == "upload" else "ОТ СЕРВЕРА" if direction == "download" else "—",
                    _display_number(metrics.get("mbps"), " Мбит/с"),
                    _display_number(metrics.get("loss_percent"), "%"),
                    _display_number(metrics.get("jitter_ms"), " мс", 2),
                    _result_status(result),
                ]
            )
        if total_width < 92:
            compact_rows = [
                [f"{row[0]} • {str(row[1]).lower()}", *row[2:]] for row in rows
            ]
            table = _semantic_table(
                ["ТОЧКА", "СКОРОСТЬ", "ПОТЕРИ", "JITTER", "СТАТУС"],
                compact_rows,
                [24, 13, 9, 10, 14],
            )
        else:
            point_width = min(38, max(18, total_width - 72))
            table = _semantic_table(
                ["ТОЧКА", "НАПРАВЛЕНИЕ", "СКОРОСТЬ", "ПОТЕРИ", "JITTER", "СТАТУС"],
                rows,
                [point_width, 12, 14, 10, 12, 16],
            )
        return ["◆ IPERF3 UDP ПО КАЖДОЙ ТОЧКЕ", *table]

    if group == "system":
        rows = []
        for result in results:
            metrics = result.get("metrics", {})
            if "logical_cpus" in metrics:
                load_average = metrics.get("load_average")
                load_text = (
                    " / ".join(_display_number(value, digits=2) for value in load_average)
                    if isinstance(load_average, list)
                    else "не определена"
                )
                ram_value = f"всего {_human_bytes(metrics.get('memtotal_bytes', 0))}"
                if metrics.get("memavailable_bytes") is not None:
                    ram_value += f", доступно {_human_bytes(metrics['memavailable_bytes'])}"
                swap_value = f"всего {_human_bytes(metrics.get('swaptotal_bytes', 0))}"
                if metrics.get("swapfree_bytes") is not None:
                    swap_value += f", свободно {_human_bytes(metrics['swapfree_bytes'])}"
                conntrack_count = metrics.get("nf_conntrack_count")
                conntrack_max = metrics.get("nf_conntrack_max")
                conntrack_utilization = metrics.get("nf_conntrack_utilization_percent")
                if (
                    not isinstance(conntrack_utilization, (int, float))
                    and str(conntrack_count).isdigit()
                    and str(conntrack_max).isdigit()
                    and int(str(conntrack_max)) > 0
                ):
                    conntrack_utilization = round(
                        int(str(conntrack_count)) / int(str(conntrack_max)) * 100,
                        2,
                    )
                conntrack_value = (
                    f"{conntrack_count} / {conntrack_max}"
                    if conntrack_count is not None and conntrack_max is not None
                    else f"не определено — {metrics.get('nf_conntrack_note') or 'счётчики ядра недоступны'}"
                )
                if isinstance(conntrack_utilization, (int, float)):
                    conntrack_value += f" ({float(conntrack_utilization):g}% заполнено)"
                    if float(conntrack_utilization) >= 90:
                        conntrack_status = "ПЛОХО"
                    elif float(conntrack_utilization) >= 70:
                        conntrack_status = "ВНИМАНИЕ"
                    else:
                        conntrack_status = "ХОРОШО"
                else:
                    conntrack_status = "НЕ ОПРЕДЕЛЕНО"
                rows.extend(
                    [
                        ["ОС", metrics.get("os") or "не определена", "ИЗМЕРЕНО"],
                        [
                            "Ядро / архитектура",
                            f"{metrics.get('kernel') or '—'} / {metrics.get('architecture') or '—'}",
                            "ИЗМЕРЕНО",
                        ],
                        ["CPU", f"{metrics.get('logical_cpus') or '?'} vCPU — {metrics.get('model') or 'модель не определена'}", "ИЗМЕРЕНО"],
                        [
                            "AES-инструкции CPU",
                            "есть" if metrics.get("aes_flag") else "не обнаружены",
                            "ИЗМЕРЕНО",
                        ],
                        ["Load average 1/5/15", load_text, "ИЗМЕРЕНО"],
                        ["RAM", ram_value, "ИЗМЕРЕНО"],
                        ["Swap", swap_value, "ИЗМЕРЕНО"],
                        [
                            "Диск /",
                            f"свободно {_human_bytes(metrics.get('root_disk_free_bytes', 0))} из {_human_bytes(metrics.get('root_disk_total_bytes', 0))}",
                            "ИЗМЕРЕНО",
                        ],
                        [
                            "IPv4",
                            metrics.get("public_ipv4") or "не определён",
                            "ИЗМЕРЕНО" if metrics.get("public_ipv4") else "НЕ ОПРЕДЕЛЕНО",
                        ],
                        [
                            "IPv6",
                            metrics.get("public_ipv6") or "не определён",
                            "ИЗМЕРЕНО" if metrics.get("public_ipv6") else "НЕ ОПРЕДЕЛЕНО",
                        ],
                        [
                            "Виртуализация",
                            metrics.get("virtualization") or "не определена",
                            "ИЗМЕРЕНО" if metrics.get("virtualization") else "НЕ ОПРЕДЕЛЕНО",
                        ],
                        [
                            "TCP congestion / qdisc",
                            f"{metrics.get('tcp_congestion_control') or 'не определён'} / {metrics.get('default_qdisc') or 'не определён'}",
                            "ИЗМЕРЕНО",
                        ],
                        [
                            "Conntrack сейчас / максимум",
                            conntrack_value,
                            conntrack_status,
                        ],
                        [
                            "NTP синхронизация",
                            metrics.get("ntp_synchronized") or "не определена",
                            "ИЗМЕРЕНО" if metrics.get("ntp_synchronized") else "НЕ ОПРЕДЕЛЕНО",
                        ],
                    ]
                )
            elif "steal_avg_percent" in metrics:
                rows.append(
                    [
                        "CPU steal (5 с)",
                        _display_number(metrics.get("steal_avg_percent"), "%"),
                        _result_status(result),
                    ]
                )
            elif result.get("category") == "crypto":
                cipher = "AES-256-GCM" if "AES" in str(result.get("name")) else "ChaCha20-Poly1305"
                crypto_mbps = _crypto_throughput_mbps(metrics)
                rows.append(
                    [
                        f"{cipher} (1 поток, 3 с)",
                        (
                            _display_number(crypto_mbps, " Мбит/с", 0)
                            if crypto_mbps is not None and crypto_mbps > 0
                            else result.get("summary", "скорость не измерена")
                        ),
                        _crypto_display_status(result, crypto_mbps),
                    ]
                )
            else:
                rows.append(
                    [
                        result.get("name", "Проверка системы"),
                        result.get("summary", "нет результата"),
                        _result_status(result),
                    ]
                )
        value_width = min(72, max(28, total_width - 50))
        return [
            "◆ РЕСУРСЫ И ПРОИЗВОДИТЕЛЬНОСТЬ",
            *_wrapped_semantic_table(
                ["ПОКАЗАТЕЛЬ", "ЗНАЧЕНИЕ", "СТАТУС"],
                rows,
                [28, value_width, 18],
            ),
        ]

    return []


def _result_sections(
    results: list[dict[str, Any]], expected_mbps: int | None
) -> list[list[str]]:
    """Keep the original order while collapsing comparable results into tables."""
    sections: list[list[str]] = []
    handled_groups: set[str] = set()
    for result in results:
        group = _tabular_group(str(result.get("category", "")))
        if group:
            if group in handled_groups:
                continue
            grouped = [
                item
                for item in results
                if _tabular_group(str(item.get("category", ""))) == group
            ]
            handled_groups.add(group)
            sections.append(_tabular_result_section(group, grouped, expected_mbps))
            continue
        sections.append(_result_card(result, expected_mbps))
    return [section for section in sections if section]


def _iperf_missing_lines(result: dict[str, Any]) -> list[str]:
    lines = [
        "◆ IPERF3 TCP      измерений нет",
        "! Программа iperf3 не установлена или не находится в PATH.",
        "· Это не низкая скорость и не отказ публичных серверов — тест не запускался.",
    ]
    if os.name == "nt":
        lines.extend(
            [
                "→ Windows: запускайте скрипт внутри Ubuntu/WSL.",
                "  1. PowerShell от администратора: wsl --install -d Ubuntu",
                "  2. После перезагрузки: wsl sudo apt-get update",
                "  3. Установка: wsl sudo apt-get install -y python3 iperf3",
                "  4. Запустите весь server_audit.py внутри WSL, не через обычный python.exe.",
            ]
        )
    else:
        lines.append("→ Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y iperf3")
    lines.append("→ После установки повторите пункт iperf3 TCP.")
    return lines


def _result_card(result: dict[str, Any], expected_mbps: int | None = None) -> list[str]:
    """Translate one technical result into a compact, test-specific explanation."""
    category = result.get("category", "")
    metrics = result.get("metrics", {})
    status = result.get("status", "failed")
    label = DISPLAY_STATUS.get(status, status.upper())
    name = result.get("name", "Проверка")

    if category == "iperf" and status == "skipped" and "не установлена" in result.get("summary", ""):
        return _iperf_missing_lines(result)

    if category == "ping" and "loss_percent" in metrics:
        loss = float(metrics["loss_percent"])
        lines = [f"◆ {name}"]
        if loss >= 100:
            lines.extend(
                [
                    "✗ ПОТЕРИ          100% — ответов на ping нет",
                    "· Сервер не обязательно выключен: firewall мог запретить ICMP.",
                    "→ Проверьте рабочий TCP-порт или запустите MTR.",
                ]
            )
            return lines
        avg = metrics.get("avg_ms")
        jitter = metrics.get("jitter_ms")
        if avg is not None and float(avg) <= 30 and loss == 0:
            assessment = "отличная задержка и стабильная связь"
        elif avg is not None and float(avg) <= 70 and loss <= 0.5:
            assessment = "хороший результат для большинства VPN-сценариев"
        elif loss <= 1 and (avg is None or float(avg) <= 120):
            assessment = "приемлемо, но стоит повторить тест в часы пик"
        else:
            assessment = "есть заметная задержка или потери; маршрут нужно перепроверить"
        lines.extend(
            [
                f"◆ СРЕДНЯЯ RTT     {_display_number(avg, ' мс')}",
                f"{'✓' if loss == 0 else '!'} ПОТЕРИ          {_display_number(loss, '%')}",
                f"  РАЗБРОС RTT     {_display_number(jitter, ' мс')}",
                f"ИТОГ [{label}]  {assessment}.",
            ]
        )
        return lines

    if category == "mtr" and metrics:
        loss = metrics.get("destination_loss_percent")
        lines = [
            f"◆ {name}",
            f"◆ СРЕДНЯЯ RTT     {_display_number(metrics.get('avg_ms'), ' мс')}",
            f"{'✓' if float(loss or 0) <= 0.5 else '✗'} ПОТЕРИ ДО ЦЕЛИ  {_display_number(loss, '%')}",
            f"  ХОПОВ           {metrics.get('hops', '?')}",
            f"ИТОГ [{label}]  "
            + ("конечная цель без заметных потерь." if float(loss or 0) <= 0.5 else "до конечной цели есть потери; маршрут нестабилен."),
        ]
        hop_rows = _mtr_hop_rows(result.get("output", ""))
        if hop_rows:
            lines.extend([_divider(), "МАРШРУТ И СТАТИСТИКА КАЖДОГО ХОПА"])
            lines.extend(
                _semantic_table(
                    ["#", "ХОП / IP", "ПОТЕРИ", "AVG", "BEST", "WORST", "JITTER"],
                    hop_rows,
                    [3, 27, 9, 9, 9, 9, 9],
                )
            )
            destination_loss = float(loss or 0)
            intermediate_loss = [
                float(str(row[2]).rstrip("%"))
                for row in hop_rows[:-1]
                if str(row[2]).rstrip("%").replace(".", "", 1).isdigit()
            ]
            if intermediate_loss and max(intermediate_loss) > max(5, destination_loss + 2):
                lines.extend(
                    [
                        "",
                        _divider(),
                        "",
                        "· Большая потеря только на промежуточном хопе при нормальной конечной строке обычно означает ограничение ICMP, а не потерю VPN-трафика.",
                    ]
                )
        return lines

    if category == "traceroute" and "hops_shown" in metrics:
        lines = [
            f"◆ {name}",
            f"◆ ХОПОВ ПОКАЗАНО  {metrics['hops_shown']}",
        ]
        hop_lines = metrics.get("hop_lines") or [
            line.rstrip()
            for line in result.get("output", "").splitlines()
            if re.match(r"^\s*\d+\s+", line)
        ]
        if hop_lines:
            hop_rows = metrics.get("hop_rows") or _traceroute_hop_rows(hop_lines)
            lines.extend([_divider(), "ПОЛНЫЙ МАРШРУТ — ВСЕ ХОПЫ"])
            lines.extend(_traceroute_table(hop_rows))
            if any("*" in line for line in hop_lines):
                lines.extend(
                    [
                        "",
                        _divider(),
                        "",
                        "· Звёздочки в строке хопа означают отсутствие ответа traceroute; это не обязательно потеря обычного VPN-трафика.",
                    ]
                )
        else:
            lines.append("! Команда завершилась без распознанных строк хопов.")
        return lines

    if category == "tcp" and "attempts" in metrics:
        success = int(metrics.get("successful_connections", 0))
        attempts = int(metrics.get("attempts", 0))
        return [
            f"◆ {name}",
            f"◆ ПОДКЛЮЧЕНИЯ     {success} из {attempts}",
            f"  ВРЕМЯ TCP       {_display_number(metrics.get('tcp_avg_ms'), ' мс')}",
            f"ИТОГ [{label}]  "
            + ("порт доступен и отвечает стабильно." if attempts and success == attempts else "порт отвечает нестабильно или недоступен с этой машины."),
        ]

    if category == "pmtu" and "path_mtu_bytes" in metrics:
        pmtu = int(metrics["path_mtu_bytes"])
        if pmtu >= 1500:
            assessment = "обычный полный MTU; проблем на этом маршруте не видно"
        elif pmtu >= 1400:
            assessment = "нормально для VPN, но MTU туннеля нужно выбрать с запасом"
        else:
            assessment = "MTU низкий; без настройки MTU/MSS возможны зависания сайтов"
        return [f"◆ {name}", f"◆ PATH MTU        {pmtu} байт", f"ИТОГ [{label}]  {assessment}."]

    if category == "iperf" and "mbps" in metrics:
        direction = metrics.get("direction")
        direction_text = "отдача с проверяемой машины" if direction == "upload" else "загрузка на проверяемую машину"
        speed = float(metrics["mbps"])
        lines = [
            f"◆ {_endpoint_name(result)} — {direction_text}",
            f"◆ СКОРОСТЬ        {_display_number(speed, ' Мбит/с')}",
        ]
        if expected_mbps:
            if speed >= expected_mbps:
                comparison = "достигает заданного ориентира"
            elif speed >= expected_mbps * 0.7:
                comparison = "немного ниже заданного ориентира"
            else:
                comparison = "заметно ниже заданного ориентира"
            lines.append(f"  ОРИЕНТИР        {expected_mbps} Мбит/с — {comparison}.")
        if metrics.get("retransmits") is not None:
            lines.append(f"  RETRANSMITS     {metrics['retransmits']}")
        return lines

    if category == "udp" and "mbps" in metrics:
        direction = "к серверу" if metrics.get("direction") != "download" else "от сервера"
        return [
            f"◆ {_endpoint_name(result)} — UDP {direction}",
            f"◆ СКОРОСТЬ        {_display_number(metrics.get('mbps'), ' Мбит/с')}",
            f"{'✓' if float(metrics.get('loss_percent', 0)) <= 0.5 else '✗'} ПОТЕРИ          {_display_number(metrics.get('loss_percent'), '%')}",
            f"  JITTER          {_display_number(metrics.get('jitter_ms'), ' мс', 2)}",
            f"ИТОГ [{label}]  " + ("UDP проходит стабильно." if status == "ok" else "есть потери или нестабильность."),
        ]

    if category == "access" and "checks" in metrics:
        checks = metrics.get("checks", [])
        available = [item["name"] for item in checks if item.get("reachable") and not item.get("access_denied")]
        failed = metrics.get("failed", [])
        denied = metrics.get("access_denied", [])
        total = len(checks)
        clear = len(available)
        gemini = next((item for item in checks if item.get("name") == "Google Gemini"), {})
        if not gemini.get("reachable"):
            gemini_text = "нет соединения"
        elif gemini.get("access_denied"):
            gemini_text = f"ответ HTTP {gemini.get('status_code')} — проверить в браузере"
        else:
            gemini_text = f"страница отвечает (HTTP {gemini.get('status_code')})"
        lines = [
            f"◆ {name}",
            f"◆ ДОСТУПНЫ        {clear} из {total}",
        ]
        if gemini:
            lines.insert(1, f"◆ GEMINI          {gemini_text}")
        if failed:
            lines.append(f"  НЕТ СОЕДИНЕНИЯ  {len(failed)}")
        if denied:
            lines.append(f"  HTTP 403/451    {len(denied)}")
        lines.extend(
            [
                f"ИТОГ [{label}]  "
                + ("явных проблем в выбранном наборе не найдено." if not failed and not denied else "часть сервисов требует ручной перепроверки."),
                _divider(),
            ]
        )
        lines.extend(_access_check_lines(checks))
        hints: list[str] = []
        if denied:
            hints.extend(
                [
                    "· HTTP 403 подтверждает сеть и TLS, но сайт отклонил автоматический запрос.",
                    "→ Перепроверьте такой сервис в обычном браузере через этот IP.",
                ]
            )
        if failed:
            hints.append("· Нет соединения — более сильный сигнал; возможны также тайм-аут, DNS или локальный firewall.")
        if gemini and (not gemini.get("reachable") or gemini.get("access_denied")):
            hints.append("· Автотест Gemini проверяет IP, DNS, TLS и страницу, но не права конкретного Google-аккаунта.")
        if hints:
            lines.extend(["", _divider(), "", *hints])
        return lines

    if category == "dnscheck" and "resolvers" in metrics:
        total = len(metrics.get("resolvers", []))
        regular = int(metrics.get("standard_working_resolvers", 0))
        encrypted = int(metrics.get("encrypted_working_resolvers", 0))
        lines = [
            f"◆ {name}",
            f"◆ ОБЫЧНЫЙ DNS     {regular} из {total} резолверов",
            f"◆ ЗАЩИЩЁННЫЙ DNS  {encrypted} из {total} резолверов",
            f"ИТОГ [{label}]  "
            + (
                "Cloudflare, Google, Quad9 и Yandex отвечают по обычному и защищённому DNS."
                if regular == total and encrypted == total
                else "часть DNS-транспортов недоступна; ниже видно, какая именно."
            ),
            _divider(),
        ]
        lines.extend(_dns_check_lines(metrics))
        if regular < total or encrypted < total or not metrics.get("system_dns", {}).get("available"):
            lines.extend(
                [
                    "",
                    _divider(),
                    "",
                    "· UDP/TCP — обычный DNS; DoT/DoH — шифрованный. Таблица показывает, какой именно транспорт не отвечает.",
                ]
            )
        return lines

    if category == "dpi" and "checks" in metrics:
        checks = metrics.get("checks", [])
        failed = metrics.get("https_failed", [])
        lines = [
            f"◆ {name}",
            f"◆ HTTPS ОТВЕЧАЕТ  {len(checks) - len(failed)} из {len(checks)}",
        ]
        if failed:
            lines.append(f"◆ БЕЗ HTTPS       {len(failed)}")
        lines.extend(
            [
                f"ИТОГ [{label}]  "
            + (
                "по выбранному списку явных признаков фильтрации не найдено."
                if not failed
                else "есть признаки фильтрации; это ещё не доказательство DPI."
            ),
                _divider(),
            ]
        )
        lines.extend(_dpi_check_lines(checks))
        if failed:
            lines.extend(
            [
                "",
                _divider(),
                "",
                "· DPI-проверка полезна прежде всего на сервере в РФ и запускается именно с него.",
                "· Тайм-аут может быть вызван маршрутом, DNS, firewall или самим сайтом — поэтому вывод вероятностный.",
            ]
            )
        return lines

    if category == "disk" and "write_fsync_mib_s" in metrics:
        return [
            f"◆ {name}",
            f"◆ ЗАПИСЬ + FSYNC  {_display_number(metrics.get('write_fsync_mib_s'), ' МиБ/с')}",
            f"  ЧТЕНИЕ          {_display_number(metrics.get('read_mib_s'), ' МиБ/с')}",
            f"ИТОГ [{label}]  " + ("для обычной VPN-ноды явной проблемы не видно." if status == "ok" else "диск медленный; для логов и баз данных возможны задержки."),
        ]

    if category == "system":
        if "steal_avg_percent" in metrics:
            steal = float(metrics["steal_avg_percent"])
            return [
                "◆ ЗАГРУЖЕННОСТЬ ХОСТА",
                f"◆ CPU STEAL       {_display_number(steal, '%')}",
                f"ИТОГ [{label}]  " + ("помех от соседних VPS почти не видно." if steal < 2 else "хост может быть перегружен; повторите вечером."),
            ]
        if "logical_cpus" in metrics:
            ram = metrics.get("memtotal_bytes", 0)
            return [
                "◆ ОСНОВНЫЕ РЕСУРСЫ",
                f"◆ CPU             {metrics.get('logical_cpus') or '?'} vCPU — {metrics.get('model') or 'модель не определена'}",
                f"◆ RAM             {_human_bytes(ram)}",
                f"  IPv4            {metrics.get('public_ipv4') or 'не определён'}",
                f"  IPv6            {metrics.get('public_ipv6') or 'не определён'}",
            ]

    if category == "crypto":
        cipher = "AES" if "AES" in name else "ChaCha20"
        crypto_mbps = _crypto_throughput_mbps(metrics)
        if crypto_mbps is None or crypto_mbps <= 0:
            return [
                f"◆ ШИФРОВАНИЕ {cipher}",
                f"ИТОГ [{_crypto_display_status(result, crypto_mbps)}]  "
                f"{result.get('summary', 'скорость не измерена')}.",
            ]
        return [
            f"◆ ШИФРОВАНИЕ {cipher}",
            f"◆ ОДИН ПРОЦЕСС    {_display_number(crypto_mbps, ' Мбит/с', 0)}",
        ]

    if category == "ipinfo" and metrics:
        countries = _country_text(metrics.get("countries", []))
        asns = ", ".join(f"AS{asn}" for asn in metrics.get("asns", [])) or "не определён"
        lines = [
            f"◆ IP-АДРЕС        {metrics.get('ip', 'не определён')}",
            f"◆ ПРОВАЙДЕР       {metrics.get('organization', 'не определён')}",
            f"◆ СЕТЬ            {asns}",
            f"◆ ГЕОЛОКАЦИЯ      {countries}",
            f"◆ РЕПУТАЦИЯ       {metrics.get('reputation_score', 'не определена')}/100",
            f"ИТОГ [{label}]  {metrics.get('verdict', result.get('summary', 'нет вывода'))}.",
        ]
        for concern in metrics.get("concerns", []):
            lines.append(f"! {concern}.")
        lines.append(_divider())
        lines.extend(_ip_provider_lines(metrics))
        return lines

    return [f"◆ {name}", f"ИТОГ [{label}]  {result.get('summary', 'нет результата')}."]


def _focused_verdict(test: str, results: list[dict[str, Any]], expected_mbps: int) -> tuple[str, str]:
    measured = [
        item
        for item in results
        if item.get("status") != "skipped"
        and (item.get("status") != "failed" or (test == "tcp" and "attempts" in item.get("metrics", {})))
    ]
    if test == "traceroute" and measured:
        hops = max(int(item.get("metrics", {}).get("hops_shown", 0)) for item in measured)
        return "ИНФОРМАЦИЯ", f"маршрут построен • показано хопов: {hops}"
    if test == "ping" and measured:
        samples = [item.get("metrics", {}) for item in measured if "loss_percent" in item.get("metrics", {})]
        if samples:
            worst_loss = max(float(item["loss_percent"]) for item in samples)
            averages = [float(item["avg_ms"]) for item in samples if item.get("avg_ms") is not None]
            jitters = [float(item["jitter_ms"]) for item in samples if item.get("jitter_ms") is not None]
            if worst_loss >= 100:
                return "ПЛОХО", "ответов на ping нет • потери: 100%"
            label = "ХОРОШО" if all(item.get("status") == "ok" for item in measured) else "ВНИМАНИЕ"
            parts = [
                f"средняя RTT: {_display_number(max(averages) if averages else None, ' мс')}",
                f"потери: {_display_number(worst_loss, '%')}",
            ]
            if jitters:
                parts.append(f"разброс: {_display_number(max(jitters), ' мс')}")
            counts = [int(item.get("transmitted", 0)) for item in samples]
            if counts and max(counts) <= 1:
                parts.append("разовый замер — стабильность не оценивается")
            elif counts and max(counts) >= 100:
                parts.append(f"расширенная выборка: {max(counts)} запросов")
            return label, " • ".join(parts)
    if test == "mtr" and measured:
        samples = [item.get("metrics", {}) for item in measured if "destination_loss_percent" in item.get("metrics", {})]
        if samples:
            worst_loss = max(float(item["destination_loss_percent"]) for item in samples)
            worst_rtt = max(float(item.get("avg_ms", 0)) for item in samples)
            label = "ХОРОШО" if worst_loss <= 0.5 else "ВНИМАНИЕ" if worst_loss <= 2 else "ПЛОХО"
            return label, f"RTT до цели: {_display_number(worst_rtt, ' мс')} • потери до цели: {_display_number(worst_loss, '%')}"
    if test == "iperf":
        speed_measurements = [
            item["metrics"] for item in results if "mbps" in item.get("metrics", {})
        ]
        speeds = [float(item["mbps"]) for item in speed_measurements]
        directions = {item.get("metrics", {}).get("direction") for item in results if "mbps" in item.get("metrics", {})}
        if not speeds:
            missing_tool = any(
                item.get("status") == "skipped" and "не установлена" in item.get("summary", "")
                for item in results
            )
            if missing_tool:
                return "НЕ ПРОВЕРЕНО", "iperf3 не установлен — тест скорости вообще не запускался"
            return "НЕ ПРОВЕРЕНО", "рабочая iperf3-точка не найдена; измерений скорости нет"
        weakest = _representative_iperf_speed(speed_measurements)
        assert weakest is not None
        profile_text = (
            " в профиле 4 потока"
            if any(item.get("streams") == 4 for item in speed_measurements)
            else ""
        )
        both = {"upload", "download"} <= directions
        if expected_mbps > 0 and weakest >= expected_mbps:
            label, text = "ХОРОШО", f"обе стороны{profile_text} достигают заданного ориентира {expected_mbps} Мбит/с"
        elif expected_mbps > 0 and weakest >= expected_mbps * 0.7:
            label, text = "ВНИМАНИЕ", f"слабейшее направление{profile_text} даёт {weakest:g} Мбит/с — немного ниже ориентира {expected_mbps}"
        elif expected_mbps > 0:
            label, text = "ПЛОХО", f"слабейшее направление{profile_text} даёт {weakest:g} Мбит/с при ориентире {expected_mbps}"
        else:
            label = _throughput_status(weakest, None)
            text = (
                f"автооценка: {weakest:g} Мбит/с в слабейшем направлении{profile_text} — "
                f"{_automatic_speed_description(weakest)}"
            )
        representative_retransmits = _representative_iperf_retransmits_per_gib(
            [
                item.get("metrics", {})
                for item in results
                if "mbps" in item.get("metrics", {})
            ]
        )
        if representative_retransmits is not None:
            retransmission_status = _iperf_retransmission_status(representative_retransmits)
            public_measurement = _iperf_measurements_are_public(speed_measurements)
            text += f" • TCP-повторы: {representative_retransmits:g}/ГиБ"
            if retransmission_status == "ПЛОХО" and public_measurement:
                if label == "ХОРОШО":
                    label = "ВНИМАНИЕ"
                text += " — высокая нагрузка могла быть на публичной точке; перепроверьте позже"
            elif retransmission_status == "ПЛОХО":
                label = "ПЛОХО"
                text += " — слишком много"
            elif (
                retransmission_status == "ВНИМАНИЕ"
                and label == "ХОРОШО"
                and not public_measurement
            ):
                label = "ВНИМАНИЕ"
                text += " — выше спокойного уровня"
        if not both:
            if label == "ХОРОШО":
                label = "ВНИМАНИЕ"
            return label, text + "; измерено не оба направления"
        return label, text
    if test == "tcp" and measured:
        tcp_results = [item for item in measured if item.get("category") == "tcp"]
        udp_results = [item for item in results if item.get("category") == "udp_port"]
        successes = [
            int(item.get("metrics", {}).get("successful_connections", 0))
            for item in tcp_results
        ]
        if successes and max(successes) == 0:
            return "ПЛОХО", "выбранный порт недоступен с этой машины"
        attempts = sum(int(item.get("metrics", {}).get("attempts", 0)) for item in tcp_results)
        success = sum(successes)
        averages = [
            float(item.get("metrics", {}).get("tcp_avg_ms", 0))
            for item in tcp_results
            if item.get("metrics", {}).get("tcp_avg_ms") is not None
        ]
        label = "ХОРОШО" if success == attempts else "ВНИМАНИЕ"
        udp_text = ""
        if udp_results:
            if any(int(item.get("metrics", {}).get("responses", 0)) for item in udp_results):
                udp_text = " • UDP-сервис ответил"
            elif any(int(item.get("metrics", {}).get("refusals", 0)) for item in udp_results):
                udp_text = " • UDP: получен явный отказ"
                label = "ВНИМАНИЕ" if label == "ХОРОШО" else label
            else:
                udp_text = " • UDP: нет ответа, состояние не определено"
                label = "ВНИМАНИЕ" if label == "ХОРОШО" else label
        return label, (
            f"TCP-подключения: {success}/{attempts} • среднее время: "
            f"{_display_number(max(averages) if averages else None, ' мс')}{udp_text}"
        )
    if test == "soak" and measured:
        stability = next((item for item in measured if item.get("category") == "soak"), None)
        throughput = next(
            (item for item in results if item.get("category") == "soak_iperf"),
            None,
        )
        labels = [
            item.get("status")
            for item in (stability, throughput)
            if item and item.get("status") != "skipped"
        ]
        if "bad" in labels:
            label = "ПЛОХО"
        elif any(item in {"warning", "failed"} for item in labels):
            label = "ВНИМАНИЕ"
        else:
            label = "ХОРОШО"
        parts = []
        if stability:
            metrics = stability.get("metrics", {})
            parts.append(
                f"потери {_display_number(metrics.get('loss_percent'), '%')}, "
                f"TCP {metrics.get('tcp_successes', 0)}/{metrics.get('tcp_attempts', 0)}, "
                f"всплески RTT {metrics.get('rtt_spike_windows', 0)}"
            )
        if throughput and "mbps" in throughput.get("metrics", {}):
            metrics = throughput["metrics"]
            parts.append(
                f"длительная скорость {_display_number(metrics.get('mbps'), ' Мбит/с')}, "
                f"снижение к концу {_display_number(metrics.get('sustained_drop_percent'), '%')}"
            )
        elif throughput:
            parts.append("burst-лимит скорости не измерен")
        return label, " • ".join(parts)
    if test == "pmtu" and measured:
        values = [int(item.get("metrics", {}).get("path_mtu_bytes", 0)) for item in measured if item.get("metrics", {}).get("path_mtu_bytes")]
        if values:
            value = min(values)
            label = "ХОРОШО" if value >= 1400 else "ВНИМАНИЕ"
            return label, f"минимальный Path MTU по целям: {value} байт"
    if test == "udp" and measured:
        samples = [item.get("metrics", {}) for item in measured if "mbps" in item.get("metrics", {})]
        if samples:
            speed = min(float(item["mbps"]) for item in samples)
            loss = max(float(item.get("loss_percent", 0)) for item in samples)
            jitter = max(float(item.get("jitter_ms", 0)) for item in samples)
            label = "ХОРОШО" if loss <= 0.5 else "ВНИМАНИЕ" if loss <= 2 else "ПЛОХО"
            return label, f"скорость: {_display_number(speed, ' Мбит/с')} • потери: {_display_number(loss, '%')} • jitter: {_display_number(jitter, ' мс', 2)}"
    if test == "access" and measured:
        checks = measured[0].get("metrics", {}).get("checks", [])
        failed = [item for item in checks if not item.get("reachable")]
        denied = [item for item in checks if item.get("access_denied")]
        if failed or denied:
            parts = []
            if failed:
                parts.append(f"нет соединения с {len(failed)} сервисом(ами)")
            if denied:
                parts.append(f"{len(denied)} сервис(а) вернули HTTP 403/451")
            label = (
                "ПЛОХО"
                if checks and len(failed) >= max(3, math.ceil(len(checks) / 2))
                else "ВНИМАНИЕ"
            )
            suffix = (
                "массовая недоступность требует проверки DNS, firewall и провайдера"
                if label == "ПЛОХО"
                else "подробности и смысл каждого ответа приведены ниже"
            )
            return label, "; ".join(parts) + f" — {suffix}"
        return "ХОРОШО", f"доступны все проверенные сервисы: {len(checks)}/{len(checks)}"
    if test == "dnscheck" and measured:
        metrics = measured[0].get("metrics", {})
        total = len(metrics.get("resolvers", []))
        regular = int(metrics.get("standard_working_resolvers", 0))
        encrypted = int(metrics.get("encrypted_working_resolvers", 0))
        system_ok = bool(metrics.get("system_dns", {}).get("available"))
        if not system_ok and regular == 0 and encrypted == 0:
            return "ПЛОХО", "DNS не работает: ни система, ни проверенные публичные резолверы не ответили"
        label = "ХОРОШО" if regular == total and encrypted == total and system_ok else "ВНИМАНИЕ"
        return label, f"обычный DNS: {regular}/{total} • защищённый DNS: {encrypted}/{total}"
    if test == "dpi" and measured:
        metrics = measured[0].get("metrics", {})
        checks = metrics.get("checks", [])
        failed = metrics.get("https_failed", [])
        if not failed:
            return "ХОРОШО", f"HTTPS отвечает у всех целей профиля: {len(checks)}/{len(checks)}"
        label = "ПЛОХО" if len(failed) >= max(4, math.ceil(len(checks) / 2)) else "ВНИМАНИЕ"
        return label, f"HTTPS не ответил у {len(failed)} из {len(checks)} целей — возможна фильтрация, нужна перепроверка"
    if test == "disk" and measured:
        metrics = measured[0].get("metrics", {})
        if "write_fsync_mib_s" in metrics:
            label = DISPLAY_STATUS.get(measured[0].get("status"), "ИНФО")
            return label, (
                f"запись: {_display_number(metrics.get('write_fsync_mib_s'), ' МиБ/с')} • "
                f"чтение: {_display_number(metrics.get('read_mib_s'), ' МиБ/с')}"
            )
    if test == "system" and measured:
        inventory = next((item.get("metrics", {}) for item in measured if "logical_cpus" in item.get("metrics", {})), {})
        steal = next((item.get("metrics", {}).get("steal_avg_percent") for item in measured if "steal_avg_percent" in item.get("metrics", {})), None)
        if inventory:
            parts = [f"{inventory.get('logical_cpus') or '?'} vCPU", f"RAM {_human_bytes(inventory.get('memtotal_bytes', 0))}"]
            if steal is not None:
                parts.append(f"CPU steal {_display_number(steal, '%')}")
            crypto_results = [item for item in results if item.get("category") == "crypto"]
            crypto_speeds = [
                speed
                for item in crypto_results
                if (speed := _crypto_throughput_mbps(item.get("metrics", {}))) is not None
                and speed > 0
            ]
            if crypto_speeds:
                parts.append(f"шифрование от {_display_number(min(crypto_speeds), ' Мбит/с', 0)}")
            elif crypto_results:
                parts.append("шифрование не измерено")
            if inventory.get("nf_conntrack_note"):
                parts.append("conntrack недоступен ядру/контейнеру")
            conntrack_utilization = inventory.get("nf_conntrack_utilization_percent")
            if isinstance(conntrack_utilization, (int, float)):
                parts.append(f"conntrack {_display_number(conntrack_utilization, '%')}")

            if steal is not None and float(steal) >= 5:
                label = "ПЛОХО"
            elif steal is not None and float(steal) >= 2:
                label = "ВНИМАНИЕ"
            else:
                label = "ХОРОШО"
            crypto_states = [
                (
                    item.get("status")
                    if item.get("status") in {"failed", "skipped"}
                    else _crypto_benchmark_assessment(
                        _crypto_throughput_mbps(item.get("metrics", {}))
                    )[0]
                )
                for item in crypto_results
            ]
            if "bad" in crypto_states:
                label = "ПЛОХО"
            elif set(crypto_states) & {"warning", "failed", "skipped"} and label == "ХОРОШО":
                label = "ВНИМАНИЕ"
            if isinstance(conntrack_utilization, (int, float)):
                if float(conntrack_utilization) >= 90:
                    label = "ПЛОХО"
                elif float(conntrack_utilization) >= 70 and label == "ХОРОШО":
                    label = "ВНИМАНИЕ"
            return label, " • ".join(parts)
    if not measured:
        return "НЕ ПРОВЕРЕНО", "измерение не выполнено; причина указана ниже"
    statuses = {item.get("status") for item in results}
    if "bad" in statuses:
        return "ПЛОХО", "обнаружена проблема, которую стоит проверить перед покупкой сервера"
    if statuses & {"warning", "failed", "skipped"}:
        return "ВНИМАНИЕ", "результат неполный или содержит предупреждения"
    return "ХОРОШО", "по этой проверке явных проблем не найдено"


def render_focused_report(report: dict[str, Any], test: str, include_raw: bool = True) -> str:
    results = report.get("results", [])
    expected = int(report.get("settings", {}).get("expected_mbps", 0))
    label, verdict = _focused_verdict(test, results, expected)
    lines = _title_banner(TEST_TITLES.get(test, "РЕЗУЛЬТАТ ПРОВЕРКИ"))
    lines.extend(["", f"ИТОГ [{label}]  {verdict}."])
    if test == "iperf" and any("mbps" in item.get("metrics", {}) for item in results):
        speed = _representative_iperf_speed(
            [item.get("metrics", {}) for item in results]
        )
        if expected > 0:
            lines.append(f"  Ручной ориентир: {expected} Мбит/с")
        elif speed is not None:
            capacity = _vpn_capacity_estimate(speed)
            users = capacity["active_users"]
            lines.extend(
                [
                    "  Режим оценки: автоматический",
                    (
                        f"  Полезный запас: ≈ {capacity['usable_mbps']:g} Мбит/с "
                        f"после резерва {capacity['reserve_percent']}%"
                    ),
                    (
                        "  Одновременно активны: "
                        f"≈ {users[10]} чел. по 10 Мбит/с · "
                        f"{users[25]} чел. по 25 Мбит/с · "
                        f"{users[50]} чел. по 50 Мбит/с"
                    ),
                ]
            )
        lines.append("  Профили TCP-потоков: 1 и 4 — выполняются автоматически")
    lines.extend(_dependency_notice_lines(report))
    lines.append("")
    sections = _result_sections(results, expected)
    for index, section in enumerate(sections):
        if index:
            lines.extend(["", _divider(), ""])
        lines.extend(line for line in section if not line.lstrip().startswith("ИТОГ ["))
    notes = report.get("notes", [])
    if notes:
        lines.extend(["", _divider(), "", *[f"· {note}" for note in notes]])
    if include_raw:
        lines.extend(_technical_details(report))
    return "\n".join(lines).rstrip() + "\n"


def render_general_report(report: dict[str, Any], include_raw: bool = True) -> str:
    score = report["score"]
    score_text = None if score["score"] is None else f"{score['score']}/100 — {score['verdict']}"
    numeric_score = score.get("score")
    if numeric_score is None:
        overall_label = "НЕ ПРОВЕРЕНО"
    elif numeric_score >= 75:
        overall_label = "ХОРОШО"
    elif numeric_score >= 60:
        overall_label = "ВНИМАНИЕ"
    else:
        overall_label = "ПЛОХО"
    lines = _title_banner("КОМПЛЕКСНАЯ ПРОВЕРКА СЕРВЕРА")
    lines.extend(["", f"Проверка {report['label']}"])
    if report.get("targets"):
        lines.append("Цели        " + ", ".join(report["targets"]))
    elif "settings" not in report:
        # Compatibility with reports created before contextual test selection.
        lines.append("Цели обычных сетевых тестов: не использовались")
    lines.extend(
        [
        (
            f"ОБЩАЯ ОЦЕНКА [{overall_label}]  {score_text} • уверенность: {score['confidence']}"
            if score_text
            else "ОБЩИЙ ИТОГ [НЕ ПРОВЕРЕНО]  общего балла нет — ниже показан результат каждого измерения"
        ),
        ]
    )
    expected = int(report.get("settings", {}).get("expected_mbps", 0))
    iperf_speed = _representative_iperf_speed(
        [
            item.get("metrics", {})
            for item in report.get("results", [])
            if item.get("category") == "iperf"
        ]
    )
    if iperf_speed is not None and expected <= 0:
        capacity = _vpn_capacity_estimate(iperf_speed)
        users = capacity["active_users"]
        lines.extend(
            [
                (
                    f"АВТООЦЕНКА КАНАЛА       {iperf_speed:g} Мбит/с в слабейшем "
                    f"направлении — {_automatic_speed_description(iperf_speed)}"
                ),
                (
                    f"РАСЧЁТНАЯ ЁМКОСТЬ       ≈ {users[10]} активных по 10 Мбит/с · "
                    f"{users[25]} по 25 Мбит/с · {users[50]} по 50 Мбит/с "
                    f"(резерв {capacity['reserve_percent']}%)"
                ),
            ]
        )
    dimension_names = {
        "latency": "Задержка",
        "stability": "Стабильность",
        "throughput": "Пропускная способность",
        "system": "Система",
    }
    if score["dimensions"]:
        lines.extend(["", _divider()])
        for key, value in score["dimensions"].items():
            lines.append(f"◆ {dimension_names.get(key, key).upper():<24} {value:.1f}/100")
    lines.extend(_dependency_notice_lines(report))
    lines.extend(["", _divider(), ""])
    sections = _result_sections(report["results"], expected)
    for index, section in enumerate(sections):
        if index:
            lines.extend(["", _divider(), ""])
        lines.extend(section)
    if report.get("notes"):
        lines.extend(["", _divider(), "", *[f"· {note}" for note in report["notes"]]])
    if include_raw:
        lines.extend(_technical_details(report))
    return "\n".join(lines).rstrip() + "\n"


def save_text_report(report: dict[str, Any], output_dir: pathlib.Path) -> pathlib.Path:
    """Save a TXT report only when the user explicitly requests it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = safe_label(report["label"])
    base = output_dir / stem
    suffix = 2
    text_path = pathlib.Path(f"{base}.txt")
    while text_path.exists():
        base = output_dir / f"{stem}_{suffix}"
        suffix += 1
        text_path = pathlib.Path(f"{base}.txt")
    plain_report = colorize_report(render_report(report), enabled=False)
    text_path.write_text(plain_report, encoding="utf-8")
    return text_path.resolve()


def save_report(report: dict[str, Any], output_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Legacy explicit export used by API callers; interactive runs do not call it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    text_path = save_text_report(report, output_dir)
    json_path = text_path.with_suffix(".json")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return json_path.resolve(), text_path.resolve()


def compare_reports(paths: list[str]) -> str:
    expanded: list[str] = []
    for path in paths:
        matches = glob.glob(path)
        expanded.extend(matches or [path])
    rows: list[tuple[float, str, str, str, str]] = []
    for path in dict.fromkeys(expanded):
        try:
            report = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
            score = report.get("score", {})
            numeric = score.get("score")
            rows.append(
                (
                    float(numeric) if numeric is not None else -1,
                    str(report.get("label", pathlib.Path(path).stem)),
                    "н/д" if numeric is None else str(numeric),
                    str(score.get("confidence", "н/д")),
                    str(score.get("verdict", "н/д")),
                )
            )
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            print(f"Не удалось прочитать {path}: {exc}", file=sys.stderr)
    rows.sort(reverse=True)
    if not rows:
        return "Нет корректных отчётов для сравнения."
    widths = [max(len(row[index]) for row in [("", "Сервер", "Баллы", "Уверенность", "Вердикт"), *rows]) for index in range(1, 5)]
    header = ("Сервер", "Баллы", "Уверенность", "Вердикт")
    lines = ["  ".join(header[index].ljust(widths[index]) for index in range(4))]
    lines.append("  ".join("-" * width for width in widths))
    for _, label, score_text, confidence, verdict in rows:
        values = (label, score_text, confidence, verdict)
        lines.append("  ".join(values[index].ljust(widths[index]) for index in range(4)))
    return "\n".join(lines)


def dependency_status(tests: set[str], *, soak_iperf: bool = False) -> dict[str, Any]:
    """Check only tools used by the selected tests; never install or mutate the host."""
    requirements: dict[str, dict[str, Any]] = {}

    def require(
        command: str,
        purpose: str,
        package: str,
        *,
        optional: bool = False,
    ) -> None:
        item = requirements.setdefault(
            command,
            {
                "command": command,
                "purposes": [],
                "package": package,
                "optional": optional,
            },
        )
        item["purposes"].append(purpose)
        item["optional"] = bool(item["optional"] and optional)

    if tests & {"ping", "pmtu", "soak"}:
        purposes = []
        if "ping" in tests:
            purposes.append("Ping")
        if "pmtu" in tests:
            purposes.append("Path MTU")
        if "soak" in tests:
            purposes.append("длительный сетевой тест")
        require("ping", " и ".join(purposes), "iputils-ping")
    if "mtr" in tests:
        require("mtr", "MTR", "mtr-tiny")
    if "traceroute" in tests:
        require(
            "tracert" if os.name == "nt" else "traceroute",
            "Traceroute",
            "traceroute",
        )
    if tests & {"iperf", "udp"} or soak_iperf:
        purposes = []
        if "iperf" in tests:
            purposes.append("iperf3 TCP")
        if "udp" in tests:
            purposes.append("iperf3 UDP")
        if soak_iperf:
            purposes.append("длительная проверка burst-лимита")
        require("iperf3", " и ".join(purposes), "iperf3")
    if "system" in tests:
        require("vmstat", "CPU steal", "procps", optional=True)
        require("openssl", "скорость AES/ChaCha", "openssl", optional=True)

    checked = []
    for item in requirements.values():
        checked.append({**item, "available": shutil.which(item["command"]) is not None})
    missing = [item for item in checked if not item["available"]]
    missing_packages = list(dict.fromkeys(str(item["package"]) for item in missing))
    if not missing:
        install_hint = None
    elif os.name == "nt":
        install_hint = (
            "Для полного набора запустите скрипт в Ubuntu/WSL; установка: "
            "sudo apt-get update && sudo apt-get install -y "
            + " ".join(missing_packages)
        )
    else:
        install_hint = (
            "sudo apt-get update && sudo apt-get install -y " + " ".join(missing_packages)
        )
    return {"checked": checked, "missing": missing, "install_hint": install_hint}


def _dependency_notice_lines(report: dict[str, Any]) -> list[str]:
    dependency = report.get("dependencies", {})
    missing = dependency.get("missing", [])
    if not missing:
        return []
    total_width = _report_table_width()
    program_width = 13
    result_width = 24
    purpose_width = max(31, total_width - program_width - result_width - 4)
    rows = [
        [
            item.get("command"),
            ", ".join(item.get("purposes", [])),
            "ЧАСТЬ ДАННЫХ ПРОПУЩЕНА" if item.get("optional") else "ТЕСТ ПРОПУЩЕН",
        ]
        for item in missing
    ]
    lines = [
        "",
        "! АВТОПРОВЕРКА: НЕ ХВАТАЕТ ПРОГРАММ ДЛЯ ЧАСТИ ВЫБРАННЫХ ТЕСТОВ",
        *_wrapped_semantic_table(
            ["ПРОГРАММА", "НУЖНА ДЛЯ", "РЕЗУЛЬТАТ"],
            rows,
            [program_width, purpose_width, result_width],
        ),
    ]
    if dependency.get("install_hint"):
        lines.extend(["", f"→ Установка: {dependency['install_hint']}"])
    lines.append("· Остальные выбранные проверки продолжают выполняться автоматически.")
    return lines


def show_test_explanations(*, color_output: bool = True) -> None:
    rows = [
        [
            "Полная проверка",
            "Запускает сеть, маршруты, скорость, систему, диск, IP, сайты, DPI и DNS. Используйте для окончательного решения о сервере; занимает больше всего времени.",
        ],
        [
            "Быстрая проверка",
            "Проверяет основные ресурсы, Ping, TCP, IP и DNS. Подходит для первичного отбора, но не подтверждает реальную скорость канала через iperf3.",
        ],
        [
            "Ping",
            "Показывает задержку до цели, потери пакетов и разброс задержки. Чем меньше RTT и разброс, тем лучше. Перед запуском можно выбрать 1 запрос для мгновенной пробы, 20 для обычного теста или 200 для оценки стабильности; один запрос потери и разброс надёжно не оценивает.",
        ],
        [
            "MTR",
            "Многократно проверяет весь маршрут и показывает задержку и потери на каждом участке. Оценивайте прежде всего последнюю строку: потери только на промежуточном хопе часто являются ограничением ICMP.",
        ],
        [
            "Traceroute",
            "Показывает, через какие узлы и сети идёт соединение до цели. Нужен для поиска странного маршрута или участка, где начинаются задержки; сам по себе скорость не измеряет.",
        ],
        [
            "TCP/UDP-порт",
            "Проверяет один номер порта обоими протоколами. TCP можно подтвердить подключением; для UDP ответ подтверждает работающий сервис, явный отказ — закрытие, а молчание означает «открыт или фильтруется».",
        ],
        [
            "Path MTU",
            "Ищет максимальный IPv4-пакет, проходящий без фрагментации. Это диагностический тест для зависающих сайтов и настройки MTU/MSS туннеля, а не общая оценка VPS.",
        ],
        [
            "iperf3 TCP",
            "Измеряет upload и download автоматически с 1 и 4 TCP-потоками. Один поток показывает скорость отдельного соединения, четыре — общую ёмкость канала. TCP-повторы публичных точек имеют пониженный вес, потому что сама точка может быть перегружена.",
        ],
        [
            "iperf3 UDP",
            "Показывает скорость, потери и jitter без повторной доставки TCP. Запускается до собственного iperf3-сервера; для VPN особенно важны низкие потери и небольшой jitter.",
        ],
        [
            "Длительный тест",
            "Пять минут периодически проверяет ping и TCP, чтобы найти короткие обрывы и всплески задержки. Если указан собственный iperf3-сервер, одновременно держит многопоточную нагрузку и ищет падение скорости после начального burst.",
        ],
        [
            "Система и CPU",
            "Показывает vCPU, RAM, диск, IPv4/IPv6, виртуализацию и CPU steal. Отдельно оценивает скорость AES/ChaCha одним процессом: это ориентир производительности шифрования, не обещанная скорость VPN.",
        ],
        [
            "Короткий диск",
            "Измеряет последовательную запись с fsync и чтение 256 МиБ. Полезен для выявления явно медленного диска; чтение может ускоряться системным кэшем и не заменяет длительный fio.",
        ],
        [
            "IP и репутация",
            "Сравнивает геолокацию, ASN, владельца сети и VPN/proxy/Tor/abuse-флаги нескольких баз. Один флаг — повод перепроверить IP, а не доказательство блокировки.",
        ],
        [
            "Доступность сайтов",
            "Проверяет DNS, соединение, HTTP и HTTPS к Gemini, ChatGPT и другим сервисам с IP этой машины. HTTP 403 может быть защитой от автоматизации; окончательную доступность Gemini проверьте в браузере с аккаунтом.",
        ],
        [
            "Цензура / DPI",
            "Сравнивает HTTP и HTTPS для набора целей Censorcheck, особенно полезно на серверах РФ. Массовые тайм-ауты похожи на фильтрацию, но одиночный сбой ещё не доказывает DPI.",
        ],
        [
            "DNS",
            "Проверяет системный DNS и Cloudflare, Google, Quad9, Yandex по UDP, TCP, DoH и DoT. Таблица показывает, какой резолвер и какой способ подключения реально работают с этого сервера.",
        ],
    ]
    test_width = 21
    value_width = max(45, _report_table_width() - test_width - 2)
    lines = _title_banner("ЧТО ОЗНАЧАЕТ КАЖДЫЙ ТЕСТ")
    lines.extend(
        [
            "",
            *_wrapped_semantic_table(
                ["ТЕСТ", "ЗНАЧЕНИЕ"],
                rows,
                [test_width, value_width],
            ),
            "",
            _divider(),
            "",
            "· Один прогон не показывает вечернюю перегрузку.",
            "· Слабый публичный iperf3 лучше повторить в другое время и сравнить со своей контрольной точкой.",
        ]
    )
    print(colorize_report("\n".join(lines).rstrip() + "\n", enabled=color_output))


def show_iperf_catalog(online: bool = True) -> None:
    endpoints, source_mode = load_ru_iperf_catalog(online=online)
    print(f"\nПубличные iperf3 РФ ({source_mode}, {len(endpoints)} endpoint):")
    print("  Источник:", RU_IPERF_CATALOG_SOURCE)
    for endpoint in sorted(endpoints, key=lambda item: (item.city, item.name)):
        ports = (
            f"{endpoint.ports[0]}-{endpoint.ports[-1]}"
            if len(endpoint.ports) > 2
            else ",".join(map(str, endpoint.ports))
        )
        print(f"  - {endpoint.city:22} {endpoint.name:32} {endpoint.host}:{ports}")


def interactive_iperf_selection() -> tuple[list[IperfEndpoint], str | None, int, str | None]:
    print(
        "\niperf3 требует вторую машину с запущенным iperf3-сервером.\n"
        "Для публичных вариантов адрес будет взят из каталога автоматически.\n"
        "Куда запускать iperf3 TCP:\n"
        "  1. РФ — обзор: Москва, Петербург, Екатеринбург, Новосибирск, Краснодар\n"
        "  2. РФ — запад/юг\n"
        "  3. РФ — Урал/Поволжье\n"
        "  4. РФ — Сибирь/Дальний Восток\n"
        "  5. РФ — выбрать города вручную\n"
        "  6. Свой iperf3-сервер\n"
        "  7. Пропустить iperf3\n"
    )
    choice = _prompt("Выберите вариант", "1")
    profiles = {"1": "ru-core", "2": "ru-west", "3": "ru-ural-volga", "4": "ru-siberia-east"}
    if choice in profiles:
        endpoints, source_mode = choose_public_iperf_endpoints(profile=profiles[choice])
        return endpoints, None, 5201, source_mode
    if choice == "5":
        catalog, source_mode = load_ru_iperf_catalog()
        cities = sorted({endpoint.city for endpoint in catalog})
        print("\nДоступные города:")
        for index, city in enumerate(cities, start=1):
            print(f"  {index:2}. {city}")
        selection = _prompt("Номера городов через запятую", "1")
        indexes: list[int] = []
        for value in selection.split(","):
            value = value.strip()
            if not value.isdigit() or not 1 <= int(value) <= len(cities):
                raise ValueError(f"Некорректный номер города: {value!r}")
            indexes.append(int(value) - 1)
        requested = [cities[index] for index in dict.fromkeys(indexes)]
        return filter_iperf_catalog(catalog, requested), None, 5201, source_mode
    if choice == "6":
        endpoint = _prompt("Свой iperf3-сервер host[:port]")
        if not endpoint:
            raise ValueError("Адрес собственного iperf3-сервера не задан")
        host, port = parse_host_port(endpoint)
        return [], host, port, "custom"
    if choice == "7":
        return [], None, 5201, None
    raise ValueError("Вариант iperf3 должен быть от 1 до 7")


def interactive_udp_server() -> tuple[str, int]:
    print(
        "\nUDP-тест можно безопасно запускать только до своего сервера.\n"
        "На второй машине должен быть запущен `iperf3 -s`, а порт разрешён в firewall."
    )
    endpoint = _prompt("Адрес второго сервера host[:port]")
    if not endpoint:
        raise ValueError("Для UDP нужен адрес собственного iperf3-сервера")
    return parse_host_port(endpoint)


def interactive_optional_udp_server() -> tuple[str | None, int]:
    print(
        "\nПубличные точки будут использованы только для TCP.\n"
        "UDP разрешено проверять только до своего iperf3-сервера."
    )
    choice = _prompt("UDP: 1 — пропустить, 2 — указать свой сервер", "1")
    if choice == "1":
        return None, 5201
    if choice == "2":
        return interactive_udp_server()
    raise ValueError("Для UDP выберите 1 или 2")


def expand_tests(value: str) -> set[str]:
    selected: set[str] = set()
    for item in value.split(","):
        key = item.strip().lower()
        if not key:
            continue
        if key not in TEST_ALIASES:
            raise ValueError(f"Неизвестный тест {key!r}")
        selected.update(TEST_ALIASES[key])
    if not selected:
        raise ValueError("Не выбран ни один тест")
    return selected


def requires_network_targets(tests: set[str]) -> bool:
    """Whether the selected tests consume ordinary ping/MTR/etc. targets."""
    return bool(tests & TARGET_TESTS)


def role_is_relevant(tests: set[str]) -> bool:
    """Compatibility helper: server roles were removed in version 1.6."""
    return False


def notes_for_tests(tests: set[str]) -> list[str]:
    notes: list[str] = []
    if "ping" in tests:
        notes.append("Ping проверяет ICMP. Сервер может работать, даже если firewall запрещает ответы на ping.")
    if "mtr" in tests:
        notes.append("Потери только на промежуточном MTR-хопе часто являются ограничением ICMP; важна конечная строка.")
    if "traceroute" in tests:
        notes.append("Traceroute показывает маршрут именно с машины, где запущен скрипт, до выбранной цели.")
    if "pmtu" in tests:
        notes.append("Path MTU — дополнительная настройка туннеля, а не оценка качества сервера.")
    if "tcp" in tests:
        notes.append("TCP подтверждается подключением; молчание UDP означает open|filtered, пока сервис или ICMP не дали явный ответ.")
    if "soak" in tests:
        notes.append("Длительный тест ищет кратковременные потери, всплески RTT, обрывы TCP и, со своей iperf3-точкой, снижение скорости после начального burst.")
    if tests & {"iperf", "udp"}:
        notes.append("iperf3 измеряет маршрут между этой машиной и выбранной iperf3-точкой; публичная точка может быть занята.")
    if "ipinfo" in tests:
        notes.append("Одиночный reputation-флаг одной геобазы — предупреждение, а не доказанный бан IP.")
    if "access" in tests:
        notes.append("HTTP 403 может быть защитой от автоматических запросов, а не блокировкой IP.")
        notes.append("Gemini окончательно проверяется в браузере: доступ зависит не только от IP, но и от аккаунта Google.")
    if "dpi" in tests:
        notes.append("DPI-тест показывает признаки фильтрации с этой машины; один тайм-аут не доказывает DPI.")
    if "dnscheck" in tests:
        notes.append("Разные IP в DNS-ответах нормальны для CDN; тест не объявляет это подменой без доказательств.")
    if "disk" in tests:
        notes.append("Короткий disk-тест выявляет явные проблемы, но не заменяет длительный fio benchmark.")
    if "system" in tests:
        notes.append("AES/ChaCha — синтетический ориентир CPU, а не обещанная скорость готового VPN-протокола.")
    return notes


def _prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or (default or "")


def _target_prompt(tests: set[str], role: str = "generic") -> str:
    _ = role
    if tests == {"ping"}:
        return "IP или домен, до которого измерить задержку"
    if tests == {"mtr"}:
        return "IP или домен, маршрут до которого проверить"
    if tests == {"traceroute"}:
        return "IP или домен, до которого построить маршрут"
    if tests == {"pmtu"}:
        return "IP или домен, до которого определить MTU"
    if tests == {"tcp"}:
        return "IP или домен сервера с проверяемым TCP/UDP-портом"
    if tests == {"soak"}:
        return "IP или домен для пятиминутного наблюдения"
    return "Адреса для сетевых тестов через запятую"


def _menu_category(title: str, *, colored: bool) -> str:
    line = f"  {title}"
    if not colored:
        return line
    return f"{ANSI['bold']}{ANSI['green']}{line}{ANSI['reset']}"


def interactive_test_selection(*, color_output: bool = True) -> set[str] | None:
    mapping = {
        "1": "full",
        "2": "quick",
        "3": "ping",
        "4": "mtr",
        "5": "traceroute",
        "6": "tcp",
        "7": "pmtu",
        "8": "iperf",
        "9": "udp",
        "10": "soak",
        "11": "system",
        "12": "disk",
        "13": "ipinfo",
        "14": "access",
        "15": "dpi",
        "16": "dnscheck",
    }
    while True:
        clear_console()
        use_menu_color = color_output and _terminal_supports_color()
        print(
            "\n"
            + "\n".join(_title_banner("SERVER SUITABILITY AUDIT  •  ГЛАВНОЕ МЕНЮ"))
            + "\n\n"
            f"{_menu_category('КОМПЛЕКСНЫЕ ПРОВЕРКИ', colored=use_menu_color)}\n"
            "   1. Полная проверка сервера\n"
            "   2. Быстрая предварительная проверка\n\n"
            f"{_menu_category('СЕТЬ И МАРШРУТ', colored=use_menu_color)}\n"
            "   3. Ping — задержка и потери\n"
            "   4. MTR — стабильность каждого участка маршрута\n"
            "   5. Traceroute — полный путь до адреса\n"
            "   6. Доступность TCP- и UDP-порта\n"
            "   7. Path MTU — диагностика размера пакетов туннеля\n\n"
            f"{_menu_category('СКОРОСТЬ И КАЧЕСТВО КАНАЛА', colored=use_menu_color)}\n"
            "   8. iperf3 TCP — upload/download с 1 и 4 потоками\n"
            "   9. iperf3 UDP — потери и jitter до своего сервера\n"
            "  10. Длительный тест — 5 минут стабильности и burst-лимитов\n\n"
            f"{_menu_category('ЖЕЛЕЗО И СИСТЕМА', colored=use_menu_color)}\n"
            "  11. Система, CPU и шифрование для VPN\n"
            "  12. Короткая проверка диска\n\n"
            f"{_menu_category('IP, СЕРВИСЫ И РЕПУТАЦИЯ', colored=use_menu_color)}\n"
            "  13. Репутация, ASN и геолокация IP\n"
            "  14. Доступность сервисов — Gemini, ChatGPT и другие\n"
            "  15. Признаки цензуры/DPI — особенно для серверов РФ\n"
            "  16. DNS — Cloudflare, Google, Quad9 и Yandex\n\n"
            f"{_menu_category('СПРАВКА', colored=use_menu_color)}\n"
            "  17. Что означает каждый тест\n\n"
            "   0. Выход\n"
        )
        raw = _prompt("Введите один или несколько номеров через запятую", "1")
        numbers = [part.strip() for part in raw.split(",") if part.strip()]
        if "0" in numbers:
            return None
        if "17" in numbers:
            clear_console()
            show_test_explanations(color_output=color_output)
            _prompt("Нажмите Enter, чтобы вернуться в меню")
            continue
        invalid = [number for number in numbers if number not in mapping]
        if invalid:
            print(f"Неизвестные пункты: {', '.join(invalid)}")
            _prompt("Нажмите Enter, чтобы снова открыть меню")
            continue
        return expand_tests(",".join(mapping[number] for number in numbers))


def interactive_config(args: argparse.Namespace) -> AuditConfig | None:
    tests = interactive_test_selection(color_output=not args.no_color)
    if tests is None:
        return None

    label = args.label or automatic_label()
    targets: list[str] = []
    if requires_network_targets(tests):
        default_targets = args.target or (
            [DEFAULT_TARGETS[0]] if tests == {"soak"} else DEFAULT_TARGETS
        )
        targets_raw = _prompt(
            _target_prompt(tests),
            ",".join(default_targets),
        )
        targets = [validate_host(value) for value in targets_raw.split(",") if value.strip()]
    else:
        targets = []
    expected = args.expected_mbps
    iperf_streams = args.iperf_streams
    iperf_available = shutil.which("iperf3") is not None
    if tests & {"iperf", "udp"} and not iperf_available:
        print(
            "\niperf3 не найден. Тест скорости будет отмечен как «не проверено», "
            "а в результате появится инструкция установки."
        )
    ping_count = args.ping_count
    if "ping" in tests:
        print(
            "\nКоличество ping-запросов:\n"
            "  1 — разовая проверка задержки\n"
            "  20 — обычная короткая проверка\n"
            "  200 — расширенная проверка стабильности"
        )
        ping_count = int(_prompt("Сколько ping-запросов отправить", str(args.ping_count)))
        validate_positive("Ping-запросы", ping_count, 1, 1_000)
    tcp_port = args.tcp_port
    if tests & {"tcp", "soak"}:
        tcp_port = int(
            _prompt(
                "Порт для TCP/UDP-наблюдения (443 для HTTPS/QUIC, 22 для SSH)",
                str(args.tcp_port),
            )
        )
        validate_positive("TCP/UDP-порт", tcp_port, 1, 65535)

    iperf_endpoints: list[IperfEndpoint] = []
    iperf_host = None
    iperf_port = 5201
    iperf_catalog_mode = None
    if "iperf" in tests and iperf_available:
        iperf_endpoints, iperf_host, iperf_port, iperf_catalog_mode = interactive_iperf_selection()
        if "udp" in tests and iperf_endpoints:
            iperf_host, iperf_port = interactive_optional_udp_server()
    elif "udp" in tests and iperf_available:
        iperf_host, iperf_port = interactive_udp_server()
        iperf_catalog_mode = "custom"
    soak_seconds = args.soak_seconds
    soak_iperf_host = None
    soak_iperf_port = 5201
    if "soak" in tests:
        soak_seconds = int(
            _prompt("Длительность наблюдения в секундах", str(args.soak_seconds))
        )
        validate_positive("Длительный тест", soak_seconds, 60, 3600)
        if iperf_available:
            print(
                "\nПроверка задержки, потерь и TCP работает без второй машины.\n"
                "Для поиска burst-лимита скорости нужен ваш собственный iperf3-сервер; "
                "публичные точки на 5 минут не используются.\n"
                "  1 — только стабильность сети\n"
                "  2 — стабильность + длительная нагрузка до своего iperf3-сервера"
            )
            soak_choice = _prompt("Выберите вариант", "1")
            if soak_choice == "2":
                endpoint = _prompt("Свой iperf3-сервер для длительной нагрузки host[:port]")
                if not endpoint:
                    raise ValueError("Для проверки burst-лимита нужен свой iperf3-сервер")
                soak_iperf_host, soak_iperf_port = parse_host_port(endpoint)
            elif soak_choice != "1":
                raise ValueError("Для длительного теста выберите 1 или 2")
    udp_mbps = args.udp_mbps
    if "udp" in tests and iperf_available and iperf_host:
        udp_mbps = int(_prompt("Какой UDP-поток отправлять, Мбит/с", str(args.udp_mbps)))
        validate_positive("UDP-поток", udp_mbps, 1, 100_000)
    check_ip = args.check_ip
    if "ipinfo" in tests and len(tests) == 1 and not check_ip:
        print("\nКакой IP проверить:\n  1 — текущий внешний IP этой машины\n  2 — указать другой IP")
        ip_choice = _prompt("Выберите вариант", "1")
        if ip_choice == "2":
            check_ip = str(ipaddress.ip_address(_prompt("Введите IP-адрес")))
        elif ip_choice != "1":
            raise ValueError("Вариант проверки IP должен быть 1 или 2")
    return AuditConfig(
        label=label,
        targets=targets,
        tests=tests,
        iperf_host=iperf_host,
        iperf_port=iperf_port,
        iperf_endpoints=iperf_endpoints,
        iperf_catalog_mode=iperf_catalog_mode,
        iperf_seconds=args.iperf_seconds,
        iperf_streams=iperf_streams,
        udp_mbps=udp_mbps,
        expected_mbps=expected,
        output_dir=pathlib.Path(args.output_dir),
        ping_count=ping_count,
        tcp_port=tcp_port,
        soak_seconds=soak_seconds,
        soak_interval_seconds=args.soak_interval,
        soak_iperf_host=soak_iperf_host,
        soak_iperf_port=soak_iperf_port,
        check_ip=check_ip,
        show_progress=not args.no_progress,
        color_output=not args.no_color,
        clear_before_report=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Интерактивная диагностика сервера для VPN и сетевого трафика",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--tests",
        help=(
            "full, quick, network или список: ping,mtr,traceroute,iperf,udp,pmtu,"
            "system,disk,tcp,soak,ipinfo,access,dpi,dnscheck"
        ),
    )
    parser.add_argument("--target", action="append", help="Цель для сетевых тестов; можно повторять")
    parser.add_argument("--role", default="generic", help=argparse.SUPPRESS)
    parser.add_argument(
        "--label",
        help="Необязательное название; без него создаётся audit_ДДММГГ_ЧЧММ",
    )
    parser.add_argument(
        "--iperf-server",
        help="Вторая машина с запущенным iperf3 -s: host[:port]",
    )
    parser.add_argument(
        "--iperf-profile",
        choices=["none", *sorted(IPERF_PROFILES)],
        default="ru-core",
        help="Набор публичных серверов РФ, если не задан --iperf-server",
    )
    parser.add_argument(
        "--iperf-city",
        action="append",
        help="Конкретный город РФ из --list-iperf-servers; можно повторять",
    )
    parser.add_argument("--iperf-seconds", type=int, default=10)
    parser.add_argument(
        "--iperf-streams",
        type=int,
        default=4,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--udp-mbps", type=int, default=50)
    parser.add_argument(
        "--expected-mbps",
        type=int,
        default=0,
        help=(
            "Ручной ориентир скорости; 0 (по умолчанию) — автоматическая оценка "
            "по фактическому каналу"
        ),
    )
    parser.add_argument(
        "--ping-count",
        type=int,
        default=20,
        help="Число запросов обычного ping: 1 для разовой проверки, 200 для стабильности",
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=443,
        help="Порт для TCP/UDP-проверки цели; например 443 или 22",
    )
    parser.add_argument(
        "--soak-seconds",
        type=int,
        default=300,
        help="Длительность теста стабильности сети",
    )
    parser.add_argument(
        "--soak-interval",
        type=int,
        default=15,
        help="Интервал между пробами длительного теста",
    )
    parser.add_argument(
        "--soak-iperf-server",
        help="Свой iperf3 host[:port] для длительной проверки burst-лимита",
    )
    parser.add_argument("--output-dir", default=DEFAULT_REPORT_DIR)
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Отключить progress bar (удобно для машинных логов)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Отключить зелёный/жёлтый/красный цвет в терминале",
    )
    parser.add_argument("--check-ip", help="Проверить указанный IP вместо текущего публичного")
    parser.add_argument("--compare", nargs="+", metavar="REPORT.json", help="Сравнить ранее сохранённые JSON")
    parser.add_argument("--explain-tests", action="store_true", help="Объяснить каждый тест и выйти")
    parser.add_argument("--list-iperf-servers", action="store_true", help="Показать актуальный каталог РФ")
    parser.add_argument("--offline-catalog", action="store_true", help="Не обновлять каталог iperf3 с GitHub")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def validate_positive(name: str, value: int, minimum: int, maximum: int) -> int:
    if not minimum <= value <= maximum:
        raise ValueError(f"{name}: допустимо от {minimum} до {maximum}")
    return value


def validate_cli_settings(args: argparse.Namespace) -> None:
    validate_positive("--iperf-seconds", args.iperf_seconds, 3, 120)
    validate_positive("--iperf-streams", args.iperf_streams, 1, 32)
    validate_positive("--udp-mbps", args.udp_mbps, 1, 100_000)
    validate_positive("--expected-mbps", args.expected_mbps, 0, 100_000)
    validate_positive("--ping-count", args.ping_count, 1, 1_000)
    validate_positive("--tcp-port", args.tcp_port, 1, 65535)
    validate_positive("--soak-seconds", args.soak_seconds, 60, 3600)
    validate_positive("--soak-interval", args.soak_interval, 5, 60)


def config_from_cli(args: argparse.Namespace) -> AuditConfig:
    tests = expand_tests(args.tests)
    default_targets = [DEFAULT_TARGETS[0]] if tests == {"soak"} else DEFAULT_TARGETS
    targets = (
        [validate_host(target) for target in (args.target or default_targets)]
        if requires_network_targets(tests)
        else []
    )
    iperf_host, iperf_port = (None, 5201)
    iperf_endpoints: list[IperfEndpoint] = []
    iperf_catalog_mode = None
    if args.iperf_server:
        iperf_host, iperf_port = parse_host_port(args.iperf_server)
        if args.iperf_city:
            raise ValueError("--iperf-server нельзя сочетать с --iperf-city")
    elif (
        "iperf" in tests
        and args.iperf_profile != "none"
        and shutil.which("iperf3") is not None
    ):
        iperf_endpoints, iperf_catalog_mode = choose_public_iperf_endpoints(
            profile=args.iperf_profile,
            cities=args.iperf_city,
            online=not args.offline_catalog,
        )
    check_ip = args.check_ip
    if check_ip:
        check_ip = str(ipaddress.ip_address(check_ip))
    soak_iperf_host = None
    soak_iperf_port = 5201
    if args.soak_iperf_server:
        if "soak" not in tests:
            raise ValueError("--soak-iperf-server используется только с --tests soak")
        soak_iperf_host, soak_iperf_port = parse_host_port(args.soak_iperf_server)
    return AuditConfig(
        label=args.label or automatic_label(),
        targets=targets,
        tests=tests,
        iperf_host=iperf_host,
        iperf_port=iperf_port,
        iperf_endpoints=iperf_endpoints,
        iperf_catalog_mode=iperf_catalog_mode,
        iperf_seconds=args.iperf_seconds,
        iperf_streams=args.iperf_streams,
        udp_mbps=args.udp_mbps,
        expected_mbps=args.expected_mbps,
        output_dir=pathlib.Path(args.output_dir),
        ping_count=args.ping_count,
        tcp_port=args.tcp_port,
        soak_seconds=args.soak_seconds,
        soak_interval_seconds=args.soak_interval,
        soak_iperf_host=soak_iperf_host,
        soak_iperf_port=soak_iperf_port,
        check_ip=check_ip,
        show_progress=not args.no_progress,
        color_output=not args.no_color,
        clear_before_report=False,
    )


def run_and_present(config: AuditConfig) -> dict[str, Any]:
    global _ACTIVE_PROGRESS
    """Run an audit and show it without writing files automatically."""
    try:
        report = run_audit(config, verbose=False)
    finally:
        if _ACTIVE_PROGRESS:
            _ACTIVE_PROGRESS.close()
            _ACTIVE_PROGRESS = None
    console_report = render_report(report, include_raw=False)
    clear_console(enabled=config.clear_before_report)
    print("\n" + colorize_report(console_report, enabled=config.color_output))
    return report


def _after_test_choice(report: dict[str, Any], config: AuditConfig) -> str:
    """Return menu, repeat or exit; TXT is exported only on explicit request."""
    while True:
        print(
            "\n" + _divider() + "\n"
            "ДЕЙСТВИЯ\n"
            "  1 — вернуться в главное меню\n"
            "  2 — сохранить подробный отчёт в TXT\n"
            "  3 — повторить эту же проверку\n"
            "  0 — выйти"
        )
        choice = _prompt("Выберите", "1")
        if choice == "2":
            try:
                text_path = save_text_report(report, config.output_dir)
            except OSError as exc:
                print(f"✗ Не удалось сохранить TXT: {exc}")
            else:
                print(f"✓ TXT сохранён: {text_path}")
            continue
        if choice in {"0", "1", "3"}:
            return {"0": "exit", "1": "menu", "3": "repeat"}[choice]
        print("Введите 0, 1, 2 или 3.")


def interactive_main(args: argparse.Namespace) -> int:
    repeat_config: AuditConfig | None = None
    while True:
        if repeat_config is None:
            try:
                config = interactive_config(args)
            except ValueError as exc:
                print(f"\nНе удалось начать проверку: {exc}")
                _prompt("Нажмите Enter, чтобы вернуться в меню")
                continue
            except (EOFError, KeyboardInterrupt):
                print("\nВыход.")
                return 0
            if config is None:
                return 0
        else:
            config = dataclasses.replace(repeat_config, label=automatic_label())
            repeat_config = None
        try:
            report = run_and_present(config)
        except KeyboardInterrupt:
            print("\nПроверка остановлена пользователем.")
            report = None
        except Exception as exc:  # keep the interactive utility alive
            print(f"\nПроверка не завершилась: {exc}")
            print("Техническая ошибка не закрыла программу; можно выбрать другой тест.")
            report = None
        try:
            if report is None:
                action = "menu" if _prompt("1 — главное меню, 0 — выход", "1") == "1" else "exit"
            else:
                action = _after_test_choice(report, config)
            if action == "exit":
                return 0
            if action == "repeat":
                repeat_config = config
        except (EOFError, KeyboardInterrupt):
            print("\nВыход.")
            return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except OSError:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.compare:
        print(compare_reports(args.compare))
        return 0
    if args.explain_tests:
        show_test_explanations(color_output=not args.no_color)
        return 0
    if args.list_iperf_servers:
        show_iperf_catalog(online=not args.offline_catalog)
        return 0
    try:
        validate_cli_settings(args)
        if args.tests:
            config = config_from_cli(args)
        elif sys.stdin.isatty():
            return interactive_main(args)
        else:
            parser.error("без интерактивного терминала укажите --tests quick или --tests full")
    except ValueError as exc:
        parser.error(str(exc))

    run_and_present(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
